# Bluetooth stage 1: HCI adapter scan

Status: implemented, **awaiting hardware validation**. Nothing here has run
on a console yet.

## Scope

A USB Bluetooth HCI adapter (tested target: CSR8510-class `0A12:0001`) is
claimed in place of a USB audio device. The plugin resets it, reads its
version and address, runs one 10.24 s general inquiry, resolves names, and logs
the results. No pairing, no connections, no ACL data, no Guide UI yet.

Build switch: `USB_AUDIO360_BLUETOOTH` (default 1 in `driver.cpp`). With 0,
Bluetooth interfaces are rejected (`bluetooth-disabled`) and the claim policy is
exactly the audio-only one. An ini key is deferred to stage 2. The current ini
parser rejects any non-`[vvvv:pppp]` section, so the ini format changes
together with link-key storage.

## Design

- **Claim:** one slot, shared by kind (`DeviceClaimGate::Kind`). The first
  claimable interface wins: a UAC playback interface or a Bluetooth primary
  HCI interface (class `E0/01/01`, alt 0, three endpoints, full-speed OHCI).
  It's matched by class, never by VID/PID. The SCO interface and anything
  plugged in while the slot is taken follow the kernel's normal path. Removal
  uses the unchanged transport detach (async close of every opened endpoint
  plus default, deferred original remove completion). The Bluetooth worker
  drives `UsbTransportRearm` the same way `AudioTick` does for audio.
- **Transport:** `UsbTransportOpen` takes the transfer type (1 isoch, 2 bulk,
  3 interrupt; audio passes 1 as before). `UsbTransportAsync` queues
  interrupt/bulk TRBs through ordinal 748 under the same ownership rules as
  control. There are no new kernel entry points.
- **Event path:** one interrupt-IN TRB of `wMaxPacketSize` (16 on CSR). The
  completion only validates status/length, copies into a 4 KB SPSC ring and
  publishes. The **worker** requeues it. In-domain requeue from the completion
  is not used, because the post-callback behaviour of the async completion
  path (unlike isoch, see the transport contract) has not been inspected.
  Events are reassembled from the ring by their header length
  (`bt::EventAssembler`), so packet boundaries don't matter.
- **Commands:** HCI class request on EP0 (`20 00 0000 0000 len`), one in
  flight. `bt::Scanner` honours `Num_HCI_Command_Packets` and applies a 5 s
  deadline per command. A USB-level control deadline marks the attachment
  failed and keeps the TRB owned until removal drains it.
- **Sequence:** Reset → Read_Local_Version → Read_BD_ADDR → Set_Event_Mask
  (default + EIR) → Write_Inquiry_Mode 2 (falls back to 1, then default) →
  Inquiry (GIAC, 8 × 1.28 s) → Remote_Name_Request for each device without an
  EIR name. A name request with no completion within 15 s ends the scan with
  the names resolved so far.
- **Portable code:** `src/bt_hci.{h,cpp}` has no Xbox dependencies and is
  covered by `tests/bt_hci_test.cpp` (run by `tools/test_uac.sh`).
- **Licensing:** written from the Bluetooth Core Specification. No BTstack
  code, and Linux `btusb` (GPL-2.0-only) is a behavioural reference only.

## Hardware gates (JTAG), in order

Use a build without other changes. Check the DashLaunch plugin slot and the
`aac.xex` base-address clash before installing.

1. **Claim and first command.** Plug in the adapter with no USB DAC attached.
   Expect in `usb_audio360.log`:
   ```
   event=device decision=claimed vid=0a12 pid=0001 ... class=e0/01/01 endpoints=3
   event=bluetooth bt-adapter attached
   event=bluetooth bt-adapter interface=0 event=0x81/16/interval1 acl_in=0x82/64 acl_out=0x02/64
   event=bluetooth bt-local hci=... manufacturer=10 (CSR)
   event=bluetooth bt-local bd_addr=..
   ```
   If no `event=device` line appears with `class=e0/..`, the kernel doesn't
   offer the adapter's interfaces to the add hook. That is the first thing to
   resolve. If `decision=rejected-profile` appears, the rejection name says why.
   Read `UsbBtDiagnostic` over XBDM:
   - [0] = `0x55414254`
   - [13] (interrupt open) ≥ 0
   - [3] event completions > 0
   - [4] status 0 or `0xc0050003`
   - [5] actual length (the TRB +0x1c) is 6 for the Reset Command Complete
   - [6] (TRB +0x18) stays 16

   These verify that ordinal 748 serves interrupt endpoints and where the
   completed length lives. Also check `UsbAudioDiagnostic[62]` = `0x00020002`.
2. **Unplug.** Expect `bt-adapter removed` within about 1–5 s, with no
   cleanup error in `UsbAudioCleanupDiagnostic[15]` and 2 closes (interrupt
   IN and default). The console must stay responsive. Replug and repeat.
3. **Scan.** Put the Bose NC 700 in pairing mode, then plug in the adapter.
   Expect `bt-inquiry start`, `bt-found addr=.. cod=0x24.... (audio/video)`,
   `bt-inquiry complete devices=N named=M`, then one `bt-device` line per
   device.
4. **Swap.** Swap adapter ↔ UAC DAC in both directions. The second device is
   only claimed after the first is removed and re-enumerated, the same policy
   as two DACs.

## UsbBtDiagnostic

| Index | Meaning |
| --- | --- |
| 0 | marker `0x55414254` |
| 1 | worker phase (0 idle, 1–2 config, 3 scanning, 4 finished, 5 failed, 6 re-arm) |
| 2 | scanner stage (`bt::Stage`) |
| 3 | event TRB completions |
| 4 | last event completion status |
| 5 | raw TRB +0x1c after the last completion (actual length) |
| 6 | raw TRB +0x18 after the last completion (requested length) |
| 7 | event ring drops |
| 8 | HCI events parsed |
| 9 | HCI commands sent |
| 10 | last control completion status |
| 11 | last error (`0xb001`… in `bluetooth.cpp`) |
| 12 | devices found |
| 13 | interrupt endpoint open status |
| 14 | unhandled/unexpected HCI events |
| 15 | rejected event completions |

## Guide page (stage 1b)

While the adapter holds the device slot, the Media tab's USB Audio row turns
into a **Bluetooth** row. Its first button opens Guide → Media → Bluetooth,
which shows:

- the adapter address
- a "Paired devices" section (empty until stage 2)
- up to six available devices from the last scan (name, or address if no
  name came back, plus device kind)
- **Scan for devices**, which starts another inquiry without resetting the
  controller

Selecting a device only shows a note for now: pairing is stage 2. The page
reads a snapshot (`BluetoothGetUiState`) and never touches USB.

## First hardware findings (COD, 2026-11-14)

- Devices plugged in at boot are enumerated before DashLaunch loads the
  plugin, so only a hot-plug reaches the add hook (boot re-enumeration only
  covers the full-speed path).
- HCD index 0/1 are EHCI (high speed, vtable 0x800DDF40) and 2/3 are OHCI
  (full speed, ISR 0x800DD518). The add-hook check `hcd[0x96] & 2` selects
  2/3. The CSR clone (bcdDevice 88.91) hot-plugged onto controller 1 (EHCI)
  and was rejected as `not-full-speed-ohci`. Next step: try another port with
  no hub in between, or put a USB 1.1 hub in front of it.

- Front port (no hub): claimed on controller 2 (OHCI). COD froze 2–3 s
  later; the last log line was `bt-step open-default`, about 30 ms after the
  claim. A claim-only build (`USB_AUDIO360_BT_CLAIM_ONLY=1`, no USB requests)
  kept COD responsive, so the hang is in or after the first default-endpoint
  open. The kernel's add event for the adapter's second interface never
  appeared before the open. `USB_AUDIO360_BT_ATTACH_SETTLE_MS` (default
  3000) now delays the first request, and `bt-open-default status=` logs the
  result.

## Next

Stage 2 adds Secure Simple Pairing, link keys in the ini, and connect/forget.
