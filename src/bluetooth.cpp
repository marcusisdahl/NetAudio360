// SPDX-License-Identifier: GPL-3.0-or-later
// Xbox side of the Bluetooth adapter: USB setup, the interrupt-IN event pump
// and the command path, driving the portable bt::Scanner. Every raw USB
// operation goes through xbox_usb_transport (USB DPC domain). Completion
// callbacks only copy results and publish them; all submission, including
// requeueing the event transfer, runs on this worker, as audio.cpp does.
#include "bluetooth.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <math.h>

#include "audio.h"
#include "bt_a2dp.h"
#include "bt_hci.h"
#include "bt_link.h"
#include "bt_sbc.h"
#include "diagnostics.h"
#include "xbox_usb_transport.h"

// Live counters for XBDM/debug inspection; see the index list below.
extern "C" volatile DWORD UsbBtDiagnostic[16] = {0};
// Kernel device-node probe (see docs/bluetooth-stage1.md). Readable over XBDM
// even when a log write to Usb0 is lost.
extern "C" volatile DWORD UsbBtProbe[16] = {0};

#ifndef USB_AUDIO360_BT_CLAIM_ONLY
#define USB_AUDIO360_BT_CLAIM_ONLY 0
#endif
// Delay between the claim and the first USB request. COD froze inside the
// first default-endpoint open when it ran ~30 ms after the claim, while the
// kernel had not yet offered the adapter's second interface.
#ifndef USB_AUDIO360_BT_ATTACH_SETTLE_MS
#define USB_AUDIO360_BT_ATTACH_SETTLE_MS 3000
#endif

namespace {

// Kernel 17559 (checked at load): one 16-byte node per device/interface;
// node+0xA indexes the default-endpoint table, which the add-complete path
// clears when it closes the enumerator's default endpoint.
DWORD* const kDefaultEndpointTable = (DWORD*)0x801A80A0;
enum ProbeIndex {
  kProbeMarker = 0,
  kProbeAfterAdd = 1,      // 1-4 node bytes 0-15, 5 default slot
  kProbeBeforeOpen = 6,    // 6-9 node bytes 0-15, 10 default slot
  kProbeOpenEndpoint = 11,
  kProbeAddCount = 12
};

void SnapshotNode(void* handle, int base, DWORD* slot_out) {
  const DWORD* node = (const DWORD*)handle;
  for (int i = 0; i < 4; ++i) UsbBtProbe[base + i] = node[i];
  DWORD slot = kDefaultEndpointTable[((const BYTE*)handle)[0xA] & 0x7F];
  UsbBtProbe[base + 4] = slot;
  if (slot_out) *slot_out = slot;
}

enum DiagnosticIndex {
  kDiagMarker = 0,          // 0x55414254 'UABT'
  kDiagPhase = 1,
  kDiagScanStage = 2,
  kDiagEventCompletions = 3,
  kDiagEventStatus = 4,
  kDiagEventActual = 5,     // Raw TRB + 0x1c after the last completion.
  kDiagEventLength = 6,     // Raw TRB + 0x18 after the last completion.
  kDiagRingDrops = 7,
  kDiagEventsParsed = 8,
  kDiagCommandsSent = 9,
  kDiagControlStatus = 10,
  kDiagError = 11,
  kDiagDevices = 12,
  kDiagOpenStatus = 13,     // Interrupt endpoint open result.
  kDiagUnhandled = 14,
  kDiagEventRejects = 15    // Completions with an unusable status/length.
};

const DWORD kControlDeadlineMs = 5000;  // Linux USB_CTRL_*_TIMEOUT.
const DWORD kRemovalSettleMs = 1000;
const DWORD kRearmRetryMs = 250;
const DWORD kRearmDeadlineMs = 5000;
const LONG kOhciDataUnderrun = (LONG)0xc0050003;

enum Phase {
  kPhaseIdle = 0,
  kPhaseConfigHeader = 1,
  kPhaseConfig = 2,
  kPhaseScanning = 3,
  kPhaseFinished = 4,
  kPhaseFailed = 5,   // Stopped; storage retained until removal drains.
  kPhaseRearm = 6,
  kPhaseSetConfig = 7,
  kPhaseGetConfig = 8
};

enum Error {
  kErrNone = 0,
  kErrOpenDefault = 0xb001,
  kErrControlSubmit = 0xb002,
  kErrControlTimeout = 0xb003,
  kErrControlStatus = 0xb004,
  kErrDescriptor = 0xb005,
  kErrOpenEvents = 0xb006,
  kErrEventSubmit = 0xb007,
  kErrEventStatus = 0xb008,
  kErrScan = 0xb009,
  kErrRearm = 0xb00a,
  kErrNoDefaultEndpoint = 0xb00b
};

// Kernel transfer request layout shared with audio.cpp. The kernel's async
// queue initialises and accumulates the completed byte count at +0x1c; for
// interrupt transfers this is verified by the first hardware run (see
// kDiagEventActual / kDiagEventLength), so the event TRB reserves the same
// storage as a control TRB.
struct UsbTrb {
  DWORD endpoint;
  DWORD callback;
  DWORD saved_endpoint;
  BYTE padding[4];
  BYTE flags;
  BYTE controller_index;
  BYTE pad2;
  BYTE endpoint_index;
  void* buffer;
  DWORD length;
};
struct UsbPacket {
  BYTE request_type;
  BYTE request;
  WORD value;
  WORD index;
  WORD length;
};
struct UsbControlTrb {
  UsbTrb trb;
  DWORD actual_length;
  UsbPacket packet;
};
typedef char BtActualOffset[offsetof(UsbControlTrb, actual_length) == 0x1c ? 1 : -1];
typedef char BtSetupOffset[offsetof(UsbControlTrb, packet) == 0x20 ? 1 : -1];

static UsbControlTrb g_control;
static UsbControlTrb g_event_trb;
static __declspec(align(128)) BYTE g_control_buffer[0x200];
static __declspec(align(128)) BYTE g_event_buffer[64];
static bt::ByteRing<4096> g_events;

// Published by the USB domain.
static void* volatile g_attached_handle = 0;
static volatile LONG g_removed = 0;
static volatile DWORD g_removed_at = 0;
static volatile DWORD g_attached_at = 0;
static bool g_settle_logged = false;
static BYTE g_configuration = 0;
static volatile LONG g_control_done = 0;
static volatile LONG g_control_status = 0;
static volatile DWORD g_control_actual = 0;
static volatile LONG g_event_pending = 0;
static volatile LONG g_event_fault = 0;
static volatile LONG g_event_fault_status = 0;

// Worker-owned.
static void* g_handle = 0;
static Phase g_phase = kPhaseIdle;
static bool g_control_pending = false;
static DWORD g_control_issued = 0;
static DWORD g_rearm_last_attempt = 0;
static bt::HciEndpoints g_endpoints;
static DWORD g_event_length = 0;
static bt::EventAssembler g_assembler;
static BYTE g_drain[256];
static WORD g_manufacturer = 0;
static volatile LONG g_scan_request = 0;

// One pending Guide request (pair/toggle/forget), guarded by g_ui_lock.
enum RequestKind { kRequestNone = 0, kRequestPair, kRequestToggle, kRequestForget };
struct Request { LONG kind; BYTE address[6]; };
static Request g_request;

// Paired devices, owned by this worker; persisted next to the ini.
static bt::PairedStore g_paired;
static bool g_paired_loaded = false;
static char g_paired_path[MAX_PATH];
static char g_paired_text[1024];
// Name for the key of the device being paired (from the search results).
static char g_pairing_name[bt::kMaxNameBytes];
static DWORD g_link_result_count = 0;
static DWORD g_link_failure = 0;
static DWORD g_link_status = 0;
static BYTE g_result_address[6];

// Guide snapshot: written by the worker, copied out by the UI thread.
static CRITICAL_SECTION g_ui_lock;
static volatile LONG g_ui_ready = 0;
static BluetoothUiState g_ui;
static BluetoothUiState g_ui_next;
static DWORD g_ui_published_at = 0;

void SetPhase(Phase phase) {
  g_phase = phase;
  UsbBtDiagnostic[kDiagPhase] = phase;
}

WORD Swap16(WORD v) { return (WORD)((v >> 8) | (v << 8)); }

// Formatting happens here on the passive worker; the diagnostics queue
// only copies. Briefly waits for a free slot rather than dropping lines.
void Log(const char* format, ...) {
  char line[320];
  va_list args;
  va_start(args, format);
  int n = _vsnprintf(line, sizeof(line) - 1, format, args);
  va_end(args);
  if (n < 0) n = sizeof(line) - 1;
  line[n] = 0;
  for (int attempt = 0; attempt < 20; ++attempt) {
    if (DiagnosticsText(line)) return;
    Sleep(10);
  }
}

// Bring-up: name each first-time USB step in the log and give the
// notification thread time to write it, so a hang points at its step.
void Step(const char* name) {
  Log("bt-step %s", name);
  Sleep(300);
}

void Fail(Error error, LONG status) {
  UsbBtDiagnostic[kDiagError] = error;
  Log("bt-error code=0x%04x status=0x%08lx phase=%u", error, (DWORD)status,
      (unsigned)g_phase);
  SetPhase(kPhaseFailed);
}

const char* MajorClass(DWORD cod) {
  static const char* names[] = {
    "misc", "computer", "phone", "network", "audio/video", "peripheral",
    "imaging", "wearable", "toy", "health"
  };
  DWORD major = (cod >> 8) & 0x1F;
  return major < sizeof(names) / sizeof(names[0]) ? names[major] : "other";
}

// Log-safe copy: control characters become '?'; UTF-8 passes through.
void Printable(const char* in, char* out, size_t capacity) {
  size_t i = 0;
  for (; in[i] && i + 1 < capacity; ++i)
    out[i] = (unsigned char)in[i] < 0x20 || in[i] == 0x7F ? '?' : in[i];
  out[i] = 0;
}

class LogObserver : public bt::ScanObserver {
 public:
  void OnLocalVersion(const bt::LocalVersion& v) {
    g_manufacturer = v.manufacturer;
    Log("bt-local hci=%u rev=0x%04x lmp=%u subver=0x%04x manufacturer=%u%s",
        v.hci_version, v.hci_revision, v.lmp_version, v.lmp_subversion,
        v.manufacturer, v.manufacturer == 10 ? " (CSR)" : "");
  }
  void OnLocalAddress(const bt::u8* address) {
    char text[18];
    bt::FormatAddress(address, text);
    Log("bt-local bd_addr=%s", text);
  }
  void OnInquiryStarted(unsigned duration_ms) {
    Log("bt-inquiry start duration_ms=%u", duration_ms);
  }
  void OnDeviceFound(const bt::Device& d) { Write("bt-found", d); }
  void OnDeviceNamed(const bt::Device& d) { Write("bt-named", d); }
  void OnWarning(unsigned stage, bt::u16 opcode, bt::u8 status) {
    Log("bt-warning stage=%s opcode=0x%04x status=0x%02x",
        bt::StageName(stage), opcode, status);
  }
  void OnComplete(const bt::Device* devices, unsigned count) {
    unsigned named = 0;
    for (unsigned i = 0; i < count; ++i)
      if (devices[i].name[0]) ++named;
    Log("bt-inquiry complete devices=%u named=%u", count, named);
    for (unsigned i = 0; i < count; ++i) Write("bt-device", devices[i]);
  }
  void OnFailed(unsigned stage, unsigned failure, bt::u16 opcode,
                bt::u8 status) {
    Log("bt-scan failed stage=%s reason=%s opcode=0x%04x status=0x%02x",
        bt::StageName(stage), bt::FailureName(failure), opcode, status);
  }

 private:
  static void Write(const char* tag, const bt::Device& d) {
    char address[18];
    char name[bt::kMaxNameBytes];
    bt::FormatAddress(d.address, address);
    Printable(d.name, name, sizeof(name));
    char rssi[16] = "n/a";
    if (d.has_rssi) _snprintf(rssi, sizeof(rssi) - 1, "%d", (int)d.rssi);
    Log("%s addr=%s cod=0x%06lx (%s) rssi=%s name=\"%s\"", tag, address,
        (DWORD)d.class_of_device, MajorClass(d.class_of_device), rssi, name);
  }
};

static LogObserver g_observer;
static bt::Scanner g_scanner(&g_observer);

// ---------------------------------------------------------------------------
// Paired-device file (passive worker only).

bool PairedPath() {
  if (g_paired_path[0]) return true;
  char ini[MAX_PATH];
  if (!DiagnosticsSettingsPath(ini, sizeof(ini))) return false;
  size_t length = strlen(ini);
  if (length < 4 || length + 1 > sizeof(g_paired_path)) return false;
  memcpy(g_paired_path, ini, length - 4);
  strcpy(g_paired_path + length - 4, ".bt");  // usb_audio360.bt
  return true;
}

void LoadPaired() {
  if (g_paired_loaded || !PairedPath()) return;
  g_paired_loaded = true;
  HANDLE f = CreateFileA(g_paired_path, GENERIC_READ, FILE_SHARE_READ, 0,
                         OPEN_EXISTING, 0, 0);
  if (f == INVALID_HANDLE_VALUE) return;  // None yet.
  DWORD high = 0, size = GetFileSize(f, &high), got = 0;
  bool ok = !high && size < sizeof(g_paired_text) &&
      ReadFile(f, g_paired_text, size, &got, 0) && got == size;
  CloseHandle(f);
  if (!ok || !g_paired.Parse(g_paired_text, size)) {
    Log("bt-paired file unreadable; starting empty");
    g_paired.Clear();
    return;
  }
  Log("bt-paired loaded devices=%u", g_paired.count());
}

void SavePaired() {
  if (!PairedPath()) return;
  unsigned n = g_paired.Format(g_paired_text, sizeof(g_paired_text));
  if (!n) return;
  HANDLE f = CreateFileA(g_paired_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, 0);
  if (f == INVALID_HANDLE_VALUE) { Log("bt-paired save failed"); return; }
  DWORD written = 0;
  bool ok = WriteFile(f, g_paired_text, n, &written, 0) && written == n &&
      FlushFileBuffers(f);
  CloseHandle(f);
  Log("bt-paired saved devices=%u ok=%u", g_paired.count(), ok ? 1u : 0u);
}

class LinkLog : public bt::LinkObserver {
 public:
  bool FindLinkKey(const bt::u8* address, bt::u8* key) {
    const bt::PairedDevice* d = g_paired.Find(address);
    if (!d) return false;
    memcpy(key, d->key, 16);
    return true;
  }
  void OnLinkKey(const bt::u8* address, const bt::u8* key, bt::u8 type) {
    char text[18];
    bt::FormatAddress(address, text);
    Log("bt-paired addr=%s key_type=%u", text, type);  // Never log the key.
    g_paired.Put(address, key, type, g_pairing_name);
    SavePaired();
  }
  void OnLinkKeyRejected(const bt::u8* address) {
    char text[18];
    bt::FormatAddress(address, text);
    Log("bt-link key rejected by addr=%s; forgetting it", text);
    if (g_paired.Remove(address)) SavePaired();
  }
  void OnLinkState(unsigned state, const bt::u8* address) {
    char text[18];
    bt::FormatAddress(address, text);
    Log("bt-link %s addr=%s", bt::LinkStateName(state), text);
    if (state == bt::kLinkConnected) {
      ++g_link_result_count;
      g_link_failure = 0;
      g_link_status = 0;
      memcpy(g_result_address, address, 6);
    }
  }
  void OnLinkFailed(unsigned failure, bt::u16 opcode, bt::u8 status,
                    const bt::u8* address) {
    char text[18];
    bt::FormatAddress(address, text);
    Log("bt-link failed reason=%s opcode=0x%04x status=0x%02x addr=%s",
        bt::LinkFailureName(failure), opcode, status, text);
    ++g_link_result_count;
    g_link_failure = failure;
    g_link_status = status;
    memcpy(g_result_address, address, 6);
  }
};

static LinkLog g_link_log;
static bt::Link g_link(&g_link_log);

// ---------------------------------------------------------------------------
// A2DP over the ACL bulk endpoints (stage 3). The bulk IN pump and the OUT
// slots follow the same rules as the event pump: callbacks copy and publish,
// the worker submits.

const unsigned kAclOutSlots = 3;
const unsigned kAclOutBytes = 1104;  // HCI ACL header + one L2CAP fragment.
const DWORD kToneMs = 2000;          // 375 Hz test tone before the system mix.
const DWORD kStreamLeadMs = 60;      // Send this far ahead of real time.
const UINT kPcmCushion = 1536;       // Captured frames kept as jitter cushion.
const UINT kPcmCeiling = 3072;       // Above this, drop back to the cushion.

enum A2dpDiagIndex {
  kA2Marker = 0,          // 0x55414144 'UAAD'
  kA2State = 1,
  kA2InCompletions = 2,
  kA2InStatus = 3,
  kA2FramesIn = 4,
  kA2OutSubmitted = 5,
  kA2OutCompletions = 6,
  kA2OutStatus = 7,
  kA2Credits = 8,
  kA2MediaPackets = 9,
  kA2SilentFrames = 10,   // PCM frames padded with silence (underrun).
  kA2OpenIn = 11,
  kA2OpenOut = 12,
  kA2SbcFrames = 13,
  kA2AclMtu = 14,
  kA2AclBuffers = 15
};

}  // namespace
// Live A2DP counters for XBDM inspection; see A2dpDiagIndex.
extern "C" volatile DWORD UsbBtA2dp[16] = {0};
namespace {

static UsbControlTrb g_acl_in_trb;
static __declspec(align(128)) BYTE g_acl_in_buffer[1024];
static DWORD g_acl_in_length = 64;
static UsbControlTrb g_acl_out_trb[kAclOutSlots];
static __declspec(align(128)) BYTE g_acl_out_buffer[kAclOutSlots][kAclOutBytes];
static volatile LONG g_acl_in_pending = 0;
static volatile LONG g_acl_out_pending[kAclOutSlots] = {0, 0, 0};
static volatile LONG g_acl_fault = 0;
static volatile LONG g_acl_fault_status = 0;
static bt::ByteRing<8192> g_acl_bytes;
static bool g_acl_ready = false;
static unsigned g_acl_credits = 0;
static bt::AclAssembler g_acl_assembler;
static BYTE g_acl_drain[512];
static BYTE g_tx_frame[1100];
static unsigned g_tx_length = 0, g_tx_offset = 0;

static bt::SbcEncoder g_sbc;
static bool g_sbc_ready = false;
static bool g_a2dp_started = false;
static bool g_tone_played = false;
static bool g_pcm_primed = false;
static DWORD g_stream_start = 0;
static DWORD g_samples_sent = 0;
static DWORD g_rtp_timestamp = 0;
static SHORT g_pcm_frame[128 * 2];
static SHORT g_pcm_scratch[128 * 2];
static BYTE g_media[1024];
static SHORT g_tone[128];
static DWORD g_audio_ui = kBluetoothAudioNone;
static DWORD g_audio_failure = 0;
static DWORD g_audio_detail = 0;

void StreamBegin() {
  g_stream_start = GetTickCount();
  g_samples_sent = 0;
  g_pcm_primed = false;
  g_sbc.Reset();
}

class A2dpLog : public bt::A2dpObserver {
 public:
  void OnA2dpState(unsigned state) {
    Log("bt-a2dp %s", bt::A2dpStateName(state));
    UsbBtA2dp[kA2State] = state;
    switch (state) {
      case bt::kA2dpStreaming:
        g_audio_ui = kBluetoothAudioPlaying;
        StreamBegin();
        break;
      case bt::kA2dpSuspended: g_audio_ui = kBluetoothAudioPaused; break;
      case bt::kA2dpIdle: g_audio_ui = kBluetoothAudioNone; break;
      case bt::kA2dpFailed: g_audio_ui = kBluetoothAudioFailed; break;
      default: g_audio_ui = kBluetoothAudioStarting; break;
    }
  }
  void OnA2dpFailed(unsigned failure, unsigned detail) {
    Log("bt-a2dp failed reason=%s detail=0x%x", bt::A2dpFailureName(failure),
        detail);
    g_audio_ui = kBluetoothAudioFailed;
    g_audio_failure = failure;
    g_audio_detail = detail;
  }
  void OnA2dpConfigured(const bt::SbcConfig& c) {
    g_sbc_ready = g_sbc.Configure(c);
    Log("bt-a2dp sbc freq=%u blocks=%u mode=%u alloc=%u bitpool=%u "
        "frame=%u ok=%u", c.frequency, c.blocks, c.channel_mode, c.allocation,
        c.bitpool, g_sbc.frame_length(), g_sbc_ready ? 1u : 0u);
  }
};

static A2dpLog g_a2dp_log;
static bt::A2dpSource g_a2dp(&g_a2dp_log);

void AclStop(const char* what, LONG status) {
  if (!g_acl_ready) return;
  g_acl_ready = false;
  Log("bt-acl stopped: %s status=0x%08x", what, (unsigned)status);
  if (g_a2dp.state() != bt::kA2dpIdle) {
    g_audio_ui = kBluetoothAudioFailed;
    g_audio_failure = 0x20;  // Transport (not a bt::A2dpFailure).
    g_audio_detail = (DWORD)status;
  }
}

void A2dpResetStream() {
  g_a2dp.Reset();
  g_acl_assembler.Reset();
  g_tx_length = g_tx_offset = 0;
  g_a2dp_started = false;
  g_sbc_ready = false;
  g_tone_played = false;
  g_acl_credits = g_scanner.acl_buffers();
  g_audio_ui = kBluetoothAudioNone;
  g_audio_failure = g_audio_detail = 0;
  UsbBtA2dp[kA2State] = 0;
}

LONG __cdecl AclInComplete(DWORD transfer, LONG status) {
  if (transfer != (DWORD)&g_acl_in_trb || !UsbTransportComplete((void*)transfer))
    return 0;
  ++UsbBtA2dp[kA2InCompletions];
  UsbBtA2dp[kA2InStatus] = (DWORD)status;
  DWORD actual = g_acl_in_trb.actual_length;
  if ((status != 0 && status != kOhciDataUnderrun) || actual > g_acl_in_length) {
    g_acl_fault_status = status;
    InterlockedExchange(&g_acl_fault, 1);
  } else if (actual) {
    g_acl_bytes.Write(g_acl_in_buffer, actual);
  }
  MemoryBarrier();
  InterlockedExchange(&g_acl_in_pending, 0);
  return 0;
}

LONG __cdecl AclOutComplete(DWORD transfer, LONG status) {
  for (unsigned i = 0; i < kAclOutSlots; ++i) {
    if (transfer != (DWORD)&g_acl_out_trb[i]) continue;
    if (!UsbTransportComplete((void*)transfer)) return 0;
    ++UsbBtA2dp[kA2OutCompletions];
    UsbBtA2dp[kA2OutStatus] = (DWORD)status;
    if (status != 0 && status != kOhciDataUnderrun) {
      g_acl_fault_status = status;
      InterlockedExchange(&g_acl_fault, 1);
    }
    MemoryBarrier();
    InterlockedExchange(&g_acl_out_pending[i], 0);
    return 0;
  }
  return 0;
}

bool QueueAclIn() {
  UsbControlTrb& t = g_acl_in_trb;
  t.trb.buffer = g_acl_in_buffer;
  t.trb.length = g_acl_in_length;
  t.actual_length = 0;
  t.trb.flags = 1;
  t.trb.callback = (DWORD)AclInComplete;
  t.trb.saved_endpoint = t.trb.endpoint;
  InterlockedExchange(&g_acl_in_pending, 1);
  LONG submitted = UsbTransportAsync(g_handle, &t);
  if (submitted < 0) {
    InterlockedExchange(&g_acl_in_pending, 0);
    AclStop("acl-in submit", submitted);
    return false;
  }
  return true;
}

// Opens both bulk endpoints after the interrupt endpoint (the transport
// tracks at most three data endpoints, which is exactly what HCI needs).
// Failure only disables audio; scanning and pairing keep working.
void OpenAcl(const bt::HciEndpoints& e) {
  g_acl_ready = false;
  g_acl_bytes.Clear();
  g_acl_assembler.Reset();
  InterlockedExchange(&g_acl_fault, 0);
  memset(&g_acl_in_trb, 0, sizeof(g_acl_in_trb));
  memset(g_acl_out_trb, 0, sizeof(g_acl_out_trb));
  for (unsigned i = 0; i < kAclOutSlots; ++i)
    InterlockedExchange(&g_acl_out_pending[i], 0);
  UsbBtA2dp[kA2Marker] = 0x55414144;
  for (int i = 1; i < 16; ++i) UsbBtA2dp[i] = 0;
  if (!e.acl_in_address || !e.acl_out_address || !e.acl_in_max_packet ||
      !e.acl_out_max_packet) {
    Log("bt-acl no bulk endpoints; audio disabled");
    return;
  }
  Step("open-acl");
  LONG status = UsbTransportOpen(g_handle, kUsbEndpointBulk, e.acl_in_address,
                                 e.acl_in_max_packet, 0,
                                 &g_acl_in_trb.trb.endpoint);
  UsbBtA2dp[kA2OpenIn] = (DWORD)status;
  DWORD out_endpoint = 0;
  LONG out_status = -1;
  if (status >= 0 && g_acl_in_trb.trb.endpoint) {
    out_status = UsbTransportOpen(g_handle, kUsbEndpointBulk, e.acl_out_address,
                                  e.acl_out_max_packet, 0, &out_endpoint);
  }
  UsbBtA2dp[kA2OpenOut] = (DWORD)out_status;
  Log("bt-acl open in=0x%08x/0x%08x out=0x%08x/0x%08x", (unsigned)status,
      (unsigned)g_acl_in_trb.trb.endpoint, (unsigned)out_status,
      (unsigned)out_endpoint);
  if (status < 0 || out_status < 0 || !g_acl_in_trb.trb.endpoint || !out_endpoint)
    return;
  for (unsigned i = 0; i < kAclOutSlots; ++i)
    g_acl_out_trb[i].trb.endpoint = out_endpoint;
  // One USB packet per IN transfer: an ACL packet that ends exactly on a
  // packet boundary is then never held back waiting for a short packet.
  g_acl_in_length = e.acl_in_max_packet;
  if (g_acl_in_length > sizeof(g_acl_in_buffer)) g_acl_in_length = sizeof(g_acl_in_buffer);
  g_acl_ready = true;
  QueueAclIn();
}

// Number Of Completed Packets (Core Vol 4 Part E 7.7.19) returns ACL credits.
void OnCompletedPackets(const BYTE* p, unsigned n) {
  if (n < 3) return;
  unsigned handles = p[2];
  for (unsigned i = 0; i < handles && 3 + 4 * i + 4 <= n; ++i) {
    const BYTE* h = p + 3 + 4 * i;
    WORD handle = (WORD)((h[0] | (h[1] << 8)) & 0x0FFF);
    WORD count = (WORD)(h[2] | (h[3] << 8));
    if (handle == g_link.handle()) g_acl_credits += count;
  }
  if (g_acl_credits > g_scanner.acl_buffers()) g_acl_credits = g_scanner.acl_buffers();
}

void AclDrain(DWORD now) {
  for (;;) {
    unsigned n = g_acl_bytes.Read(g_acl_drain, sizeof(g_acl_drain));
    if (!n) return;
    unsigned used = 0;
    while (used < n) {
      bool complete = false;
      used += g_acl_assembler.Push(g_acl_drain + used, n - used, &complete);
      if (!complete) continue;
      ++UsbBtA2dp[kA2FramesIn];
      if (g_link.busy() && g_acl_assembler.handle() == g_link.handle())
        g_a2dp.OnFrame(g_acl_assembler.frame(), g_acl_assembler.frame_length(), now);
    }
  }
}

void AclTransmit() {
  for (;;) {
    if (g_tx_offset >= g_tx_length) {
      if (!g_a2dp.HasOutput()) return;
      unsigned n = 0;
      const BYTE* frame = g_a2dp.Output(&n);
      if (n <= sizeof(g_tx_frame)) {
        memcpy(g_tx_frame, frame, n);
        g_tx_length = n;
        g_tx_offset = 0;
      }
      g_a2dp.PopOutput();
      continue;
    }
    if (!g_acl_credits) return;
    unsigned slot = kAclOutSlots;
    for (unsigned i = 0; i < kAclOutSlots && slot == kAclOutSlots; ++i)
      if (!g_acl_out_pending[i]) slot = i;
    if (slot == kAclOutSlots) return;
    unsigned mtu = g_scanner.acl_mtu();
    if (mtu > kAclOutBytes - 4) mtu = kAclOutBytes - 4;
    unsigned chunk = g_tx_length - g_tx_offset;
    if (chunk > mtu) chunk = mtu;
    BYTE* p = g_acl_out_buffer[slot];
    // Packet boundary: 2 = first flushable fragment, 1 = continuation.
    WORD header = (WORD)((g_link.handle() & 0x0FFF) |
                         (g_tx_offset ? 0x1000 : 0x2000));
    p[0] = (BYTE)header;
    p[1] = (BYTE)(header >> 8);
    p[2] = (BYTE)chunk;
    p[3] = (BYTE)(chunk >> 8);
    memcpy(p + 4, g_tx_frame + g_tx_offset, chunk);
    UsbControlTrb& t = g_acl_out_trb[slot];
    t.trb.buffer = p;
    t.trb.length = 4 + chunk;
    t.actual_length = 0;
    t.trb.flags = 1;
    t.trb.callback = (DWORD)AclOutComplete;
    t.trb.saved_endpoint = t.trb.endpoint;
    InterlockedExchange(&g_acl_out_pending[slot], 1);
    LONG submitted = UsbTransportAsync(g_handle, &t);
    if (submitted < 0) {
      InterlockedExchange(&g_acl_out_pending[slot], 0);
      AclStop("acl-out submit", submitted);
      return;
    }
    ++UsbBtA2dp[kA2OutSubmitted];
    --g_acl_credits;
    g_tx_offset += chunk;
  }
}

// One SBC frame of PCM: the test tone first, then the captured system mix.
void FillPcm(DWORD now) {
  const unsigned spf = g_sbc.samples_per_frame();
  if (!g_tone_played && now - g_stream_start < kToneMs) {
    for (unsigned i = 0; i < spf; ++i)
      g_pcm_frame[2 * i] = g_pcm_frame[2 * i + 1] = g_tone[i & 127];
    return;
  }
  if (!g_tone_played) {
    g_tone_played = true;
    g_pcm_primed = false;
    AudioDiscardBluetoothPcm();  // The ring holds stale audio from before.
    Log("bt-a2dp test tone done; streaming console audio");
  }
  UINT available = AudioBluetoothPcmAvailable();
  if (!g_pcm_primed) {
    if (available < kPcmCushion) {
      memset(g_pcm_frame, 0, spf * 4);
      return;
    }
    g_pcm_primed = true;
  }
  while (available > kPcmCeiling) {
    UINT drop = available - kPcmCushion;
    if (drop > 128) drop = 128;
    AudioReadBluetoothPcm(g_pcm_scratch, drop);
    available = AudioBluetoothPcmAvailable();
  }
  UINT got = AudioReadBluetoothPcm(g_pcm_frame, spf);
  if (got < spf) {
    memset(g_pcm_frame + 2 * got, 0, (spf - got) * 4);
    UsbBtA2dp[kA2SilentFrames] += spf - got;
    if (!got) g_pcm_primed = false;  // Rebuild the cushion after a gap.
  }
}

void StreamAudio(DWORD now) {
  if (!g_a2dp.streaming() || !g_sbc_ready) return;
  const unsigned spf = g_sbc.samples_per_frame();
  const unsigned frame = g_sbc.frame_length();
  if (!spf || spf > 128 || !frame) return;
  // Media payload: RTP header (12) + SBC header (1) + frames, limited by the
  // remote MTU, our buffers and what the controller can hold in flight.
  unsigned budget = g_a2dp.media_mtu();
  unsigned acl = g_scanner.acl_mtu() * g_scanner.acl_buffers();
  if (acl > 4 && acl - 4 < budget) budget = acl - 4;
  if (budget > sizeof(g_media) + 13) budget = sizeof(g_media) + 13;
  if (budget < 13 + frame) return;
  unsigned per = (budget - 13) / frame;
  if (per > 15) per = 15;
  DWORD target = (now - g_stream_start + kStreamLeadMs) * 48;
  if ((LONG)(target - g_samples_sent) > 48 * 300) {
    // Stalled (flow control or a slow tick): skip ahead instead of bursting.
    DWORD skip = target - g_samples_sent - 48 * kStreamLeadMs;
    g_samples_sent += skip;
    g_rtp_timestamp += skip;
  }
  while ((LONG)(target - g_samples_sent) >= (LONG)(per * spf)) {
    if (g_a2dp.free_slots() < 3) return;  // Keep room for signalling.
    unsigned bytes = 0;
    for (unsigned f = 0; f < per; ++f) {
      FillPcm(now);
      bytes += g_sbc.Encode(g_pcm_frame, g_media + bytes);
    }
    UsbBtA2dp[kA2SbcFrames] += per;
    if (g_a2dp.SendMedia(g_media, bytes, per, g_rtp_timestamp))
      ++UsbBtA2dp[kA2MediaPackets];
    g_rtp_timestamp += per * spf;
    g_samples_sent += per * spf;
  }
}

void AclTick(DWORD now) {
  if (!g_acl_ready) return;
  if (g_acl_fault) { AclStop("transfer failed", g_acl_fault_status); return; }
  if (!g_acl_in_pending) {
    MemoryBarrier();
    AclDrain(now);
    if (!QueueAclIn()) return;
  }
  AclDrain(now);
  if (!g_link.busy()) {
    if (g_a2dp_started || g_a2dp.state() != bt::kA2dpIdle) A2dpResetStream();
    g_acl_credits = g_scanner.acl_buffers();
    return;
  }
  if (g_link.state() == bt::kLinkConnected) {
    if (!g_a2dp_started) {
      g_a2dp_started = true;
      bool ok = g_a2dp.Start(now);
      Log("bt-a2dp start ok=%u acl_mtu=%u acl_buffers=%u", ok ? 1u : 0u,
          g_scanner.acl_mtu(), g_scanner.acl_buffers());
    }
    StreamAudio(now);
  }
  AclTransmit();
  g_a2dp.Tick(now);
  UsbBtA2dp[kA2Credits] = g_acl_credits;
  UsbBtA2dp[kA2AclMtu] = g_scanner.acl_mtu();
  UsbBtA2dp[kA2AclBuffers] = g_scanner.acl_buffers();
}

bool AudioActive() {
  return g_acl_ready && g_a2dp.state() != bt::kA2dpIdle &&
         g_a2dp.state() != bt::kA2dpFailed;
}

// ---------------------------------------------------------------------------
// USB-domain callbacks: copy, publish, return.

LONG __cdecl ControlComplete(DWORD transfer, LONG status) {
  if (transfer != (DWORD)&g_control || !UsbTransportComplete((void*)transfer))
    return 0;
  g_control_actual = g_control.actual_length;
  g_control_status = status;
  MemoryBarrier();
  InterlockedExchange(&g_control_done, 1);
  return 0;
}

LONG __cdecl EventComplete(DWORD transfer, LONG status) {
  if (transfer != (DWORD)&g_event_trb || !UsbTransportComplete((void*)transfer))
    return 0;
  ++UsbBtDiagnostic[kDiagEventCompletions];
  UsbBtDiagnostic[kDiagEventStatus] = (DWORD)status;
  UsbBtDiagnostic[kDiagEventActual] = g_event_trb.actual_length;
  UsbBtDiagnostic[kDiagEventLength] = g_event_trb.trb.length;
  DWORD actual = g_event_trb.actual_length;
  // Short interrupt IN is normal for HCI events. Only success and OHCI
  // DataUnderrun (short packet) are accepted; anything else stops the pump.
  if ((status != 0 && status != kOhciDataUnderrun) || actual > g_event_length) {
    ++UsbBtDiagnostic[kDiagEventRejects];
    g_event_fault_status = status;
    InterlockedExchange(&g_event_fault, 1);
  } else if (actual && !g_events.Write(g_event_buffer, actual)) {
    UsbBtDiagnostic[kDiagRingDrops] = g_events.dropped();
  }
  MemoryBarrier();
  InterlockedExchange(&g_event_pending, 0);
  return 0;
}

// ---------------------------------------------------------------------------
// Worker-side submission.

bool QueueControl(BYTE type, BYTE request, WORD value, WORD index,
                  WORD length) {
  if (g_control_pending || length > sizeof(g_control_buffer)) return false;
  g_control.packet.request_type = type;
  g_control.packet.request = request;
  g_control.packet.value = Swap16(value);
  g_control.packet.index = Swap16(index);
  g_control.packet.length = Swap16(length);
  g_control.trb.buffer = g_control_buffer;
  g_control.trb.length = length;
  g_control.actual_length = 0;
  g_control.trb.flags = 1;  // Accept short IN; actual length validated.
  g_control.trb.callback = (DWORD)ControlComplete;
  g_control.trb.saved_endpoint = g_control.trb.endpoint;
  InterlockedExchange(&g_control_done, 0);
  g_control_pending = true;
  g_control_issued = GetTickCount();
  LONG submitted = UsbTransportControl(g_handle, &g_control);
  if (submitted < 0) {
    // Not accepted by the adapter: ownership was never taken.
    g_control_pending = false;
    Fail(kErrControlSubmit, submitted);
    return false;
  }
  return true;
}

// Returns 1 when the pending control transfer completed successfully,
// 0 while pending, -1 after failure (phase is already Failed).
// tolerate_status: a completed transfer with an error status returns 2 (with
// *status) instead of failing the attachment.
int PollControl(DWORD* actual, bool tolerate_status = false,
                LONG* status_out = 0) {
  if (!g_control_pending) return -1;
  if (!g_control_done) {
    if (GetTickCount() - g_control_issued >= kControlDeadlineMs) {
      // Storage stays owned by the host; this attachment never reuses it.
      Fail(kErrControlTimeout, 0);
    }
    return g_phase == kPhaseFailed ? -1 : 0;
  }
  MemoryBarrier();
  g_control_pending = false;
  LONG status = g_control_status;
  UsbBtDiagnostic[kDiagControlStatus] = (DWORD)status;
  if (status_out) *status_out = status;
  if (status != 0 && status != kOhciDataUnderrun && tolerate_status) {
    if (actual) *actual = 0;
    return 2;
  }
  if (status != 0 && status != kOhciDataUnderrun) {
    Fail(kErrControlStatus, status);
    return -1;
  }
  DWORD n = g_control_actual;
  if (n > g_control.trb.length) {
    Fail(kErrControlStatus, (LONG)n);
    return -1;
  }
  if (actual) *actual = n;
  return 1;
}

bool QueueEvent() {
  g_event_trb.trb.buffer = g_event_buffer;
  g_event_trb.trb.length = g_event_length;
  g_event_trb.actual_length = 0;
  g_event_trb.trb.flags = 1;
  g_event_trb.trb.callback = (DWORD)EventComplete;
  g_event_trb.trb.saved_endpoint = g_event_trb.trb.endpoint;
  InterlockedExchange(&g_event_pending, 1);
  LONG submitted = UsbTransportAsync(g_handle, &g_event_trb);
  if (submitted < 0) {
    InterlockedExchange(&g_event_pending, 0);
    Fail(kErrEventSubmit, submitted);
    return false;
  }
  return true;
}

void DrainEvents(DWORD now) {
  for (;;) {
    unsigned n = g_events.Read(g_drain, sizeof(g_drain));
    if (!n) return;
    size_t used = 0;
    while (used < n) {
      bool complete = false;
      used += g_assembler.Push(g_drain + used, n - used, &complete);
      if (!complete) continue;
      ++UsbBtDiagnostic[kDiagEventsParsed];
      if (g_assembler.buffer()[0] == 0x13) {  // ACL credits, not for the link.
        OnCompletedPackets(g_assembler.buffer(), g_assembler.length());
        continue;
      }
      // Setup and searches belong to the scanner; once it is done, the
      // link layer owns the controller.
      if (!g_scanner.finished())
        g_scanner.OnEvent(g_assembler.buffer(), g_assembler.length(), now);
      else
        g_link.OnEvent(g_assembler.buffer(), g_assembler.length(), now);
    }
  }
}

void StartAttachment() {
  g_handle = g_attached_handle;
  memset(&g_control, 0, sizeof(g_control));
  memset(&g_event_trb, 0, sizeof(g_event_trb));
  memset(&g_endpoints, 0, sizeof(g_endpoints));
  g_events.Clear();
  g_assembler.Reset();
  g_control_pending = false;
  g_manufacturer = 0;
  InterlockedExchange(&g_scan_request, 0);
  InterlockedExchange(&g_event_fault, 0);
  g_link.Reset();
  g_acl_ready = false;
  A2dpResetStream();
  LoadPaired();
  for (int i = 1; i < 16; ++i) UsbBtDiagnostic[i] = 0;
  Log("bt-adapter attached");
#if USB_AUDIO360_BT_CLAIM_ONLY
  // Bring-up control: keep the claim but issue no USB requests at all.
  Log("bt-claim-only build: no USB requests will be sent");
  SetPhase(kPhaseFailed);
  return;
#endif
  Log("bt-node after-add %08x %08x %08x %08x default-slot=0x%08x adds=%u",
      (unsigned)UsbBtProbe[kProbeAfterAdd], (unsigned)UsbBtProbe[kProbeAfterAdd + 1],
      (unsigned)UsbBtProbe[kProbeAfterAdd + 2], (unsigned)UsbBtProbe[kProbeAfterAdd + 3],
      (unsigned)UsbBtProbe[kProbeAfterAdd + 4], (unsigned)UsbBtProbe[kProbeAddCount]);
  DWORD slot = 0;
  SnapshotNode(g_handle, kProbeBeforeOpen, &slot);
  Log("bt-node before-open %08x %08x %08x %08x default-slot=0x%08x",
      (unsigned)UsbBtProbe[kProbeBeforeOpen], (unsigned)UsbBtProbe[kProbeBeforeOpen + 1],
      (unsigned)UsbBtProbe[kProbeBeforeOpen + 2], (unsigned)UsbBtProbe[kProbeBeforeOpen + 3],
      (unsigned)slot);
  Step("open-default");
  LONG status = UsbTransportOpenDefault(g_handle, &g_control.trb.endpoint);
  UsbBtProbe[kProbeOpenEndpoint] = g_control.trb.endpoint;
  Log("bt-open-default status=0x%08x endpoint=0x%08x", (unsigned)status,
      (unsigned)g_control.trb.endpoint);
  if (status < 0) { Fail(kErrOpenDefault, status); return; }
  if (!g_control.trb.endpoint) {
    // The kernel closed this device's default endpoint when the add hook
    // completed. A control transfer on a NULL endpoint wedges the USB DPC.
    Log("bt-adapter has no default endpoint; stopping without USB requests");
    Fail(kErrNoDefaultEndpoint, 0);
    return;
  }
  SetPhase(kPhaseConfigHeader);
  Step("get-configuration");
  QueueControl(0x80, 6, 0x0200, 0, 9);  // GET_DESCRIPTOR(configuration)
}

void ConfigTick() {
  DWORD actual = 0;
  LONG status = 0;
  // GET/SET_CONFIGURATION failures are reported, not fatal: the CSR clone
  // stalls SET_CONFIGURATION, apparently because the kernel's enumerator
  // already selected the configuration.
  const bool tolerate = g_phase == kPhaseGetConfig || g_phase == kPhaseSetConfig;
  int polled = PollControl(&actual, tolerate, &status);
  if (polled <= 0) return;
  if (g_phase == kPhaseConfigHeader) {
    if (actual < 4 || g_control_buffer[1] != 2) { Fail(kErrDescriptor, actual); return; }
    WORD total = (WORD)(g_control_buffer[2] | (g_control_buffer[3] << 8));
    if (total < 9) { Fail(kErrDescriptor, total); return; }
    if (total > sizeof(g_control_buffer)) total = sizeof(g_control_buffer);
    SetPhase(kPhaseConfig);
    QueueControl(0x80, 6, 0x0200, 0, total);
    return;
  }
  if (g_phase == kPhaseConfig) {
    if (!bt::FindHciEndpoints(g_control_buffer, actual, &g_endpoints)) {
      Fail(kErrDescriptor, actual);
      return;
    }
    // Like the audio path: select the configuration before using any
    // non-default endpoint (bConfigurationValue at offset 5).
    g_configuration = g_control_buffer[5];
    SetPhase(kPhaseGetConfig);
    Step("get-active-configuration");
    QueueControl(0x80, 8, 0, 0, 1);  // GET_CONFIGURATION
    return;
  }
  if (g_phase == kPhaseGetConfig) {
    BYTE active = (polled == 1 && actual >= 1) ? g_control_buffer[0] : 0;
    Log("bt-configuration wanted=%u active=%u status=0x%08x",
        (unsigned)g_configuration, (unsigned)active, (unsigned)status);
    if (active != g_configuration) {
      SetPhase(kPhaseSetConfig);
      Step("set-configuration");
      QueueControl(0x00, 9, g_configuration, 0, 0);
      return;
    }
  } else if (g_phase == kPhaseSetConfig && polled == 2) {
    Log("bt-warning set-configuration status=0x%08x; continuing",
        (unsigned)status);
  }
  const bt::HciEndpoints& e = g_endpoints;
  Log("bt-adapter interface=%u event=0x%02x/%u/interval%u acl_in=0x%02x/%u "
      "acl_out=0x%02x/%u", e.interface_number, e.event_address,
      e.event_max_packet, e.event_interval, e.acl_in_address,
      e.acl_in_max_packet, e.acl_out_address, e.acl_out_max_packet);
  g_event_length = e.event_max_packet;
  if (g_event_length > sizeof(g_event_buffer)) g_event_length = sizeof(g_event_buffer);
  Step("open-interrupt");
  status = UsbTransportOpen(g_handle, kUsbEndpointInterrupt,
                                 e.event_address, e.event_max_packet,
                                 e.event_interval ? e.event_interval : 1,
                                 &g_event_trb.trb.endpoint);
  UsbBtDiagnostic[kDiagOpenStatus] = (DWORD)status;
  if (status < 0) { Fail(kErrOpenEvents, status); return; }
  Step("queue-interrupt");
  if (!QueueEvent()) return;
  OpenAcl(e);
  Step("hci-scan");
  SetPhase(kPhaseScanning);
  // Setup only: the adapter never scans until the Guide asks for it.
  g_scanner.Start(GetTickCount(), false);
}

void ScanTick() {
  DWORD now = GetTickCount();
  if (g_event_fault) { Fail(kErrEventStatus, g_event_fault_status); return; }
  // Events first so a Command Complete that raced the control completion is
  // seen before the next command is considered.
  if (!g_event_pending) {
    MemoryBarrier();
    DrainEvents(now);
    if (!QueueEvent()) return;
  }
  DrainEvents(now);
  if (g_control_pending) {
    int result = PollControl(0);
    if (result < 0) { g_scanner.Abort(bt::kFailTransport, 0); return; }
  }
  if (!g_control_pending) {
    BYTE command[bt::kMaxCommandBytes];
    unsigned n = g_scanner.NextCommand(command, sizeof(command));
    if (n) {
      memcpy(g_control_buffer, command, n);
      // HCI command: class request to the device (Core Vol 4 Part B 2.2).
      if (!QueueControl(0x20, 0, 0, 0, (WORD)n)) {
        g_scanner.Abort(bt::kFailTransport, 0);
        return;
      }
      g_scanner.CommandSent(now);
      ++UsbBtDiagnostic[kDiagCommandsSent];
    }
  }
  g_scanner.Tick(now);
  UsbBtDiagnostic[kDiagScanStage] = g_scanner.stage();
  UsbBtDiagnostic[kDiagDevices] = g_scanner.device_count();
  UsbBtDiagnostic[kDiagUnhandled] = g_scanner.unhandled_events();
  UsbBtDiagnostic[kDiagRingDrops] = g_events.dropped();
  if (g_scanner.stage() == bt::kStageDone) SetPhase(kPhaseFinished);
  else if (g_scanner.stage() == bt::kStageFailed) Fail(kErrScan, 0);
}

Request TakeRequest() {
  Request request = {kRequestNone};
  EnterCriticalSection(&g_ui_lock);
  request = g_request;
  g_request.kind = kRequestNone;
  LeaveCriticalSection(&g_ui_lock);
  return request;
}

void HandleRequest(const Request& request, DWORD now) {
  char text[18];
  bt::FormatAddress(request.address, text);
  switch (request.kind) {
    case kRequestPair: {
      if (g_link.busy()) return;
      const bt::Device* found = 0;
      for (unsigned i = 0; i < g_scanner.device_count(); ++i)
        if (!memcmp(g_scanner.devices()[i].address, request.address, 6))
          found = &g_scanner.devices()[i];
      if (!found) return;
      memcpy(g_pairing_name, found->name, sizeof(g_pairing_name));
      Log("bt-link pair requested addr=%s", text);
      g_link.Connect(*found, now);
      break;
    }
    case kRequestToggle: {
      if (g_link.busy()) {
        if (!memcmp(g_link.address(), request.address, 6)) {
          Log("bt-link disconnect requested addr=%s", text);
          g_link.Disconnect(now);
        }
        return;
      }
      const bt::PairedDevice* d = g_paired.Find(request.address);
      if (!d) return;
      memcpy(g_pairing_name, d->name, sizeof(g_pairing_name));
      Log("bt-link connect requested addr=%s", text);
      g_link.Connect(request.address, now);
      break;
    }
    case kRequestForget:
      if (g_link.busy() && !memcmp(g_link.address(), request.address, 6))
        g_link.Disconnect(now);
      if (g_paired.Remove(request.address)) {
        Log("bt-paired forgot addr=%s", text);
        SavePaired();
      }
      break;
  }
}

void FinishedTick() {
  // The controller is set up; the link layer owns it until the next search.
  DWORD now = GetTickCount();
  if (g_event_fault) { Fail(kErrEventStatus, g_event_fault_status); return; }
  if (!g_event_pending) {
    MemoryBarrier();
    DrainEvents(now);
    if (!QueueEvent()) return;
  }
  DrainEvents(now);
  Request request = TakeRequest();
  if (request.kind != kRequestNone) HandleRequest(request, now);
  if (!g_link.busy() && InterlockedExchange(&g_scan_request, 0) &&
      g_scanner.Rescan(now)) {
    Log("bt-inquiry rescan requested");
    SetPhase(kPhaseScanning);
    return;
  }
  if (g_control_pending) {
    int result = PollControl(0);
    if (result < 0) { g_link.Abort(0); return; }
  }
  if (!g_control_pending) {
    BYTE command[bt::kMaxCommandBytes];
    unsigned n = g_link.NextCommand(command, sizeof(command));
    if (n) {
      memcpy(g_control_buffer, command, n);
      if (!QueueControl(0x20, 0, 0, 0, (WORD)n)) {
        g_link.Abort(0);
        return;
      }
      g_link.CommandSent(now);
      ++UsbBtDiagnostic[kDiagCommandsSent];
    }
  }
  g_link.Tick(now);
  AclTick(now);
  UsbBtDiagnostic[kDiagUnhandled] =
      g_scanner.unhandled_events() + g_link.unhandled_events();
}

void RearmTick() {
  DWORD now = GetTickCount();
  DWORD elapsed = now - g_removed_at;
  if (elapsed < kRemovalSettleMs) return;
  if (elapsed >= kRearmDeadlineMs) {
    // Fail closed: storage stays retained and the claim stays draining.
    if (UsbBtDiagnostic[kDiagError] != kErrRearm) {
      UsbBtDiagnostic[kDiagError] = kErrRearm;
      Log("bt-error code=0x%04x drain/re-arm deadline", kErrRearm);
    }
    return;
  }
  if (now - g_rearm_last_attempt < kRearmRetryMs) return;
  g_rearm_last_attempt = now;
  if (!UsbTransportRearm()) return;
  g_handle = 0;
  g_control_pending = false;
  InterlockedExchange(&g_event_pending, 0);
  InterlockedExchange(&g_removed, 0);
  g_link.Reset();  // The controller and its links are gone.
  g_acl_ready = false;
  InterlockedExchange(&g_acl_in_pending, 0);
  for (unsigned i = 0; i < kAclOutSlots; ++i)
    InterlockedExchange(&g_acl_out_pending[i], 0);
  A2dpResetStream();
  SetPhase(kPhaseIdle);
  Log("bt-adapter removed");
}

DWORD UiStatus() {
  switch (g_phase) {
    case kPhaseConfigHeader:
    case kPhaseConfig:
    case kPhaseSetConfig:
    case kPhaseGetConfig:
      return kBluetoothStarting;
    case kPhaseScanning:
      return g_scanner.stage() >= bt::kStageInquiry ? kBluetoothScanning
                                                    : kBluetoothStarting;
    case kPhaseFinished:
      return g_scanner.inquiries() ? kBluetoothReady : kBluetoothIdle;
    case kPhaseFailed: return kBluetoothError;
    default: return kBluetoothNoAdapter;
  }
}

void PublishUi(bool force) {
  DWORD now = GetTickCount();
  if (!force && now - g_ui_published_at < 100) return;
  g_ui_published_at = now;
  BluetoothUiState& n = g_ui_next;
  memset(&n, 0, sizeof(n));
  n.status = UiStatus();
  n.error = UsbBtDiagnostic[kDiagError];
  if (n.status != kBluetoothNoAdapter) {
    const BYTE* local = g_scanner.local_address();
    for (int i = 0; i < 6; ++i) if (local[i]) n.address_valid = TRUE;
    if (n.address_valid) memcpy(n.address, local, 6);
    n.manufacturer = g_manufacturer;
  }
  n.paired_count = g_paired.count();
  for (unsigned i = 0; i < g_paired.count() && i < 3; ++i) {
    memcpy(n.paired[i].address, g_paired.at(i).address, 6);
    memcpy(n.paired[i].name, g_paired.at(i).name, sizeof(n.paired[i].name));
    n.paired[i].name[sizeof(n.paired[i].name) - 1] = 0;
  }
  if (n.status != kBluetoothNoAdapter && g_link.busy()) {
    switch (g_link.state()) {
      case bt::kLinkConnected: n.link = kBluetoothLinkConnected; break;
      case bt::kLinkDisconnecting: n.link = kBluetoothLinkDisconnecting; break;
      default: n.link = kBluetoothLinkConnecting; break;
    }
    memcpy(n.link_address, g_link.address(), 6);
    n.link_paired_now = g_link.paired_now() ? TRUE : FALSE;
    if (g_link.state() == bt::kLinkConnected) {
      n.audio = g_audio_ui;
      n.audio_failure = g_audio_failure;
      n.audio_detail = g_audio_detail;
    }
  }
  n.link_result_count = g_link_result_count;
  n.link_failure = g_link_failure;
  n.link_status = g_link_status;
  memcpy(n.result_address, g_result_address, 6);
  if (n.status == kBluetoothScanning || n.status == kBluetoothReady) {
    // kBluetoothIdle has no list: nothing has been searched yet.
    unsigned count = g_scanner.device_count();
    if (count > 16) count = 16;
    n.device_count = count;
    for (unsigned i = 0; i < count; ++i) {
      const bt::Device& d = g_scanner.devices()[i];
      BluetoothUiDevice& u = n.devices[i];
      memcpy(u.address, d.address, 6);
      u.class_of_device = d.class_of_device;
      u.rssi = d.rssi;
      u.has_rssi = d.has_rssi ? TRUE : FALSE;
      memcpy(u.name, d.name, sizeof(u.name));
      u.name[sizeof(u.name) - 1] = 0;
    }
  }
  EnterCriticalSection(&g_ui_lock);
  n.sequence = g_ui.sequence;
  if (memcmp(&n, &g_ui, sizeof(n)) != 0) {
    n.sequence = g_ui.sequence + 1;
    memcpy(&g_ui, &n, sizeof(n));
  }
  LeaveCriticalSection(&g_ui_lock);
}

void Tick() {
  if (g_removed && g_phase != kPhaseRearm) {
    g_rearm_last_attempt = g_removed_at;
    SetPhase(kPhaseRearm);
  }
  switch (g_phase) {
    case kPhaseIdle:
      if (!g_attached_handle || g_removed) { g_settle_logged = false; break; }
      if (!g_settle_logged) {
        g_settle_logged = true;
        Log("bt-adapter claimed; waiting %u ms before the first USB request",
            (unsigned)USB_AUDIO360_BT_ATTACH_SETTLE_MS);
      }
      if (GetTickCount() - g_attached_at < USB_AUDIO360_BT_ATTACH_SETTLE_MS) break;
      g_settle_logged = false;
      StartAttachment();
      break;
    case kPhaseConfigHeader:
    case kPhaseConfig:
    case kPhaseSetConfig:
    case kPhaseGetConfig:
      ConfigTick();
      break;
    case kPhaseScanning:
      ScanTick();
      break;
    case kPhaseFinished:
      FinishedTick();
      break;
    case kPhaseRearm:
      RearmTick();
      break;
    case kPhaseFailed:
      break;
  }
  PublishUi(false);
}

}  // namespace

VOID BluetoothRecordAddComplete(void* handle) {
  UsbBtProbe[kProbeMarker] = 0x55414250;  // 'UABP'
  ++UsbBtProbe[kProbeAddCount];
  if (handle) SnapshotNode(handle, kProbeAfterAdd, 0);
}

VOID BluetoothDeviceAttached(void* handle) {
  g_attached_at = GetTickCount();
  MemoryBarrier();
  g_attached_handle = handle;
}

VOID BluetoothDeviceRemoved() {
  g_attached_handle = 0;
  g_removed_at = GetTickCount();
  MemoryBarrier();
  InterlockedExchange(&g_removed, 1);
}

BOOL BluetoothGetUiState(BluetoothUiState* state) {
  if (!state || !g_ui_ready) return FALSE;
  EnterCriticalSection(&g_ui_lock);
  memcpy(state, &g_ui, sizeof(*state));
  LeaveCriticalSection(&g_ui_lock);
  return TRUE;
}

VOID BluetoothRequestScan() {
  InterlockedExchange(&g_scan_request, 1);
}

static VOID PostRequest(LONG kind, const BYTE* address) {
  if (!g_ui_ready || !address) return;
  EnterCriticalSection(&g_ui_lock);
  g_request.kind = kind;
  memcpy(g_request.address, address, 6);
  LeaveCriticalSection(&g_ui_lock);
}

VOID BluetoothRequestPair(const BYTE* address) { PostRequest(kRequestPair, address); }
VOID BluetoothRequestToggle(const BYTE* address) { PostRequest(kRequestToggle, address); }
VOID BluetoothRequestForget(const BYTE* address) { PostRequest(kRequestForget, address); }

BOOL BluetoothAdapterPresent() {
  BluetoothUiState state;
  return BluetoothGetUiState(&state) && state.status != kBluetoothNoAdapter;
}

DWORD WINAPI BluetoothWorker(void*) {
  UsbBtDiagnostic[kDiagMarker] = 0x55414254;
  memset(&g_ui, 0, sizeof(g_ui));
  InitializeCriticalSection(&g_ui_lock);
  for (int i = 0; i < 128; ++i)  // 375 Hz: exactly one period per SBC frame.
    g_tone[i] = (SHORT)(8000.0f * sinf(6.2831853f * (float)i / 128.0f));
  MemoryBarrier();
  InterlockedExchange(&g_ui_ready, 1);
  for (;;) {
    // Show saved pairings even before an adapter is plugged in.
    if (!g_paired_loaded && DiagnosticsSettingsPath(g_paired_text, MAX_PATH))
      LoadPaired();
    Tick();
    Sleep(AudioActive() || g_phase == kPhaseScanning || g_phase == kPhaseConfig ||
          g_phase == kPhaseConfigHeader || g_phase == kPhaseSetConfig ||
          g_phase == kPhaseGetConfig ? 1 : 20);
  }
}
