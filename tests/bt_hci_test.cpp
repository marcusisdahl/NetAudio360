// SPDX-License-Identifier: GPL-3.0-or-later
// Host tests for the portable HCI layer. Byte sequences are written from the
// Bluetooth Core Specification event/command formats.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "bt_hci.h"

using namespace bt;

namespace {

struct Recorder : ScanObserver {
  Recorder() { memset(this->found_names, 0, sizeof(found_names)); Clear(); }
  void Clear() {
    versions = addresses = inquiries = found = named = warnings = 0;
    completed = failed = 0;
    complete_count = 0;
    fail_stage = fail_reason = 0;
    fail_opcode = 0;
    fail_status = warn_status = 0;
    warn_opcode = 0;
    inquiry_ms = 0;
    memset(&version, 0, sizeof(version));
  }
  void OnLocalVersion(const LocalVersion& v) { ++versions; version = v; }
  void OnLocalAddress(const u8* a) { ++addresses; memcpy(address, a, 6); }
  void OnInquiryStarted(unsigned ms) { ++inquiries; inquiry_ms = ms; }
  void OnDeviceFound(const Device& d) {
    if (found < 4) strcpy(found_names[found], d.name);
    ++found;
  }
  void OnDeviceNamed(const Device&) { ++named; }
  void OnWarning(unsigned, u16 opcode, u8 status) {
    ++warnings; warn_opcode = opcode; warn_status = status;
  }
  void OnComplete(const Device*, unsigned count) { ++completed; complete_count = count; }
  void OnFailed(unsigned stage, unsigned failure, u16 opcode, u8 status) {
    ++failed; fail_stage = stage; fail_reason = failure;
    fail_opcode = opcode; fail_status = status;
  }
  int versions, addresses, inquiries, found, named, warnings, completed, failed;
  unsigned complete_count, fail_stage, fail_reason, inquiry_ms;
  u16 fail_opcode, warn_opcode;
  u8 fail_status, warn_status;
  LocalVersion version;
  u8 address[6];
  char found_names[4][kMaxNameBytes];
};

// Sends the scanner's next command and checks its bytes.
void ExpectCommand(Scanner& s, const u8* expected, unsigned length,
                   unsigned now) {
  u8 out[kMaxCommandBytes];
  unsigned n = s.NextCommand(out, sizeof(out));
  assert(n == length);
  assert(!memcmp(out, expected, length));
  // A second call before CommandSent repeats the same command, nothing new.
  assert(s.NextCommand(out, sizeof(out)) == length);
  s.CommandSent(now);
  assert(s.NextCommand(out, sizeof(out)) == 0);
}

void Feed(Scanner& s, const u8* event, unsigned now) {
  s.OnEvent(event, 2u + event[1], now);
}

void CommandComplete(Scanner& s, u16 opcode, const u8* ret, u8 n,
                     unsigned now) {
  u8 e[kMaxEventBytes];
  e[0] = kEvCommandComplete; e[1] = (u8)(3 + n);
  e[2] = 1; e[3] = (u8)opcode; e[4] = (u8)(opcode >> 8);
  memcpy(e + 5, ret, n);
  Feed(s, e, now);
}

void CommandStatus(Scanner& s, u16 opcode, u8 status, unsigned now) {
  u8 e[6] = {kEvCommandStatus, 4, status, 1, (u8)opcode, (u8)(opcode >> 8)};
  Feed(s, e, now);
}

// Write_Simple_Pairing_Mode(1) and Write_Local_Name("Xbox 360"), each
// answered with the given status.
void SetupTail(Scanner& s, unsigned* now, u8 ssp_status, u8 name_status) {
  const u8 ssp[] = {0x56, 0x0C, 0x01, 0x01};
  ExpectCommand(s, ssp, sizeof(ssp), *now);
  CommandComplete(s, kOpWriteSimplePairingMode, &ssp_status, 1, ++*now);
  u8 name[3 + 248];
  memset(name, 0, sizeof(name));
  name[0] = 0x13; name[1] = 0x0C; name[2] = 248;
  memcpy(name + 3, "Xbox 360", 8);
  ExpectCommand(s, name, sizeof(name), *now);
  CommandComplete(s, kOpWriteLocalName, &name_status, 1, ++*now);
}

const u8 kBose[6] = {0x11, 0x22, 0x33, 0x5D, 0x87, 0x4C};
const u8 kPhone[6] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6};
const u8 kLocal[6] = {0x01, 0x02, 0x03, 0x7D, 0x1A, 0x00};

// Drives Reset .. Write_Inquiry_Mode to the start of Inquiry.
void RunSetup(Scanner& s, Recorder& r, unsigned* now, bool inquire = true) {
  const u8 ok[] = {0};
  s.Start(*now, inquire);
  assert(s.stage() == kStageReset);
  const u8 reset[] = {0x03, 0x0C, 0x00};
  ExpectCommand(s, reset, 3, *now);
  CommandComplete(s, kOpReset, ok, 1, ++*now);

  const u8 version[] = {0x01, 0x10, 0x00};
  ExpectCommand(s, version, 3, *now);
  const u8 version_ret[] = {0, 6, 0xBB, 0x22, 6, 0x0A, 0x00, 0xBB, 0x22};
  CommandComplete(s, kOpReadLocalVersion, version_ret, 9, ++*now);
  assert(r.versions == 1 && r.version.manufacturer == 10 &&
         r.version.hci_revision == 0x22BB && r.version.lmp_version == 6);

  const u8 addr[] = {0x09, 0x10, 0x00};
  ExpectCommand(s, addr, 3, *now);
  u8 addr_ret[7] = {0};
  memcpy(addr_ret + 1, kLocal, 6);
  CommandComplete(s, kOpReadBdAddr, addr_ret, 7, ++*now);
  assert(r.addresses == 1 && !memcmp(s.local_address(), kLocal, 6));

  const u8 bufsize[] = {0x05, 0x10, 0x00};
  ExpectCommand(s, bufsize, 3, *now);
  const u8 bufsize_ret[] = {0, 0x36, 0x01, 0x40, 0x0A, 0x00, 0x08, 0x00};
  CommandComplete(s, kOpReadBufferSize, bufsize_ret, 8, ++*now);
  assert(s.acl_mtu() == 310 && s.acl_buffers() == 10);

  const u8 mask[] = {0x01, 0x0C, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDF, 0xBF, 0x1C};
  ExpectCommand(s, mask, sizeof(mask), *now);
  CommandComplete(s, kOpSetEventMask, ok, 1, ++*now);

  const u8 mode[] = {0x45, 0x0C, 0x01, 0x02};
  ExpectCommand(s, mode, sizeof(mode), *now);
  CommandComplete(s, kOpWriteInquiryMode, ok, 1, ++*now);
  SetupTail(s, now, 0, 0);
  assert(s.stage() == (inquire ? kStageInquiry : kStageDone));
}

void TestDescriptors() {
  // Typical CSR8510 configuration: HCI interface 0 and SCO interface 1.
  u8 c[] = {
    0x09, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00, 0xE0, 0x32,
    0x09, 0x04, 0x00, 0x00, 0x03, 0xE0, 0x01, 0x01, 0x00,
    0x07, 0x05, 0x81, 0x03, 0x10, 0x00, 0x01,
    0x07, 0x05, 0x82, 0x02, 0x40, 0x00, 0x01,
    0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x01,
    0x09, 0x04, 0x01, 0x00, 0x02, 0xE0, 0x01, 0x01, 0x00,
    0x07, 0x05, 0x83, 0x01, 0x00, 0x00, 0x01,
    0x07, 0x05, 0x03, 0x01, 0x00, 0x00, 0x01,
    0x09, 0x04, 0x01, 0x01, 0x02, 0xE0, 0x01, 0x01, 0x00,
    0x07, 0x05, 0x83, 0x01, 0x09, 0x00, 0x01,
    0x07, 0x05, 0x03, 0x01, 0x09, 0x00, 0x01,
  };
  c[2] = sizeof(c);
  HciEndpoints e;
  assert(FindHciEndpoints(c, sizeof(c), &e));
  assert(e.interface_number == 0);
  assert(e.event_address == 0x81 && e.event_max_packet == 16 && e.event_interval == 1);
  assert(e.acl_in_address == 0x82 && e.acl_in_max_packet == 64);
  assert(e.acl_out_address == 0x02 && e.acl_out_max_packet == 64);

  // Truncated mid-endpoint: rejected rather than read past the end.
  assert(!FindHciEndpoints(c, 30, &e));
  // Missing bulk OUT on the primary interface: no match.
  u8 bad[sizeof(c)];
  memcpy(bad, c, sizeof(c));
  bad[34] = 0x83;  // bulk OUT -> second bulk IN
  assert(!FindHciEndpoints(bad, sizeof(bad), &e));
  // An audio interface is not mistaken for HCI.
  memcpy(bad, c, sizeof(c));
  bad[14] = 0x01;
  assert(!FindHciEndpoints(bad, sizeof(bad), &e));
  // Zero-length descriptor is malformed.
  memcpy(bad, c, sizeof(c));
  bad[18] = 0;
  assert(!FindHciEndpoints(bad, sizeof(bad), &e));
}

void TestAssembler() {
  // Extended Inquiry Result (2 + 255 bytes) arrives in 16-byte packets,
  // immediately followed by a Command Status in the final packet.
  u8 stream[2 + 255 + 6];
  stream[0] = kEvExtendedInquiryResult; stream[1] = 255;
  for (unsigned i = 2; i < 257; ++i) stream[i] = (u8)i;
  const u8 status[] = {kEvCommandStatus, 4, 0, 1, 0x19, 0x04};
  memcpy(stream + 257, status, 6);

  EventAssembler a;
  unsigned events = 0, offset = 0;
  while (offset < sizeof(stream)) {
    unsigned chunk = sizeof(stream) - offset < 16 ? sizeof(stream) - offset : 16;
    size_t used = 0;
    while (used < chunk) {
      bool complete = false;
      used += a.Push(stream + offset + used, chunk - used, &complete);
      if (!complete) continue;
      ++events;
      if (events == 1) {
        assert(a.length() == 257 && !memcmp(a.buffer(), stream, 257));
      } else {
        assert(a.length() == 6 && !memcmp(a.buffer(), status, 6));
      }
    }
    offset += chunk;
  }
  assert(events == 2 && !a.partial());

  // Header split across chunks, zero-parameter event.
  bool complete = false;
  const u8 h1[] = {0x0E};
  const u8 h2[] = {0x00};
  assert(a.Push(h1, 1, &complete) == 1 && !complete && a.partial());
  assert(a.Push(h2, 1, &complete) == 1 && complete && a.length() == 2);
}

void TestNames() {
  char name[kMaxNameBytes];
  const u8 eir[] = {
    0x02, 0x01, 0x06,                            // flags
    0x05, 0x08, 'B', 'o', 's', 'e',              // shortened
    0x0F, 0x09, 'B', 'o', 's', 'e', ' ', 'N', 'C', ' ', '7', '0', '0',
    ' ', 'H', 'P',                               // complete wins
    0x00, 0xAA, 0xBB,                            // terminator + padding
  };
  assert(EirName(eir, sizeof(eir), name, sizeof(name)));
  assert(!strcmp(name, "Bose NC 700 HP"));
  assert(EirName(eir, 9, name, sizeof(name)) && !strcmp(name, "Bose"));
  const u8 none[] = {0x02, 0x01, 0x06, 0x00};
  assert(!EirName(none, sizeof(none), name, sizeof(name)));
  const u8 overrun[] = {0x09, 0x09, 'A'};
  assert(!EirName(overrun, sizeof(overrun), name, sizeof(name)));

  // Truncation never leaves half a UTF-8 character ("Ø" = C3 98).
  const u8 utf8[] = {'a', 'b', 0xC3, 0x98, 'c'};
  char small[4];
  CopyName(utf8, sizeof(utf8), small, sizeof(small));
  assert(!strcmp(small, "ab"));
  char big[8];
  CopyName(utf8, sizeof(utf8), big, sizeof(big));
  assert(!strcmp(big, "ab\xC3\x98" "c"));

  char text[18];
  FormatAddress(kBose, text);
  assert(!strcmp(text, "4C:87:5D:33:22:11"));
}

void TestFullScan() {
  Recorder r;
  Scanner s(&r);
  unsigned now = 0xFFFFFF00u;  // Exercise tick wrap-around.
  RunSetup(s, r, &now);

  const u8 inquiry[] = {0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x08, 0x00};
  ExpectCommand(s, inquiry, sizeof(inquiry), now);
  CommandStatus(s, kOpInquiry, 0, ++now);
  assert(r.inquiries == 1 && r.inquiry_ms == 10240);

  // Extended Inquiry Result from the headphones, with name.
  u8 eir_event[2 + 255];
  memset(eir_event, 0, sizeof(eir_event));
  eir_event[0] = kEvExtendedInquiryResult; eir_event[1] = 255;
  u8* p = eir_event + 2;
  p[0] = 1;
  memcpy(p + 1, kBose, 6);
  p[7] = 1;                                          // page scan rep mode R1
  p[9] = 0x04; p[10] = 0x04; p[11] = 0x24;           // CoD 0x240404
  p[12] = 0x34; p[13] = 0x12;                        // clock offset
  p[14] = (u8)-52;                                   // RSSI
  const char bose[] = "Bose NC 700 HP";
  p[15] = (u8)(sizeof(bose)); p[16] = 0x09;
  memcpy(p + 17, bose, sizeof(bose) - 1);
  Feed(s, eir_event, ++now);
  // Repeated responses update, not duplicate.
  Feed(s, eir_event, ++now);

  // Inquiry Result with RSSI from a device that sent no name.
  u8 rssi[2 + 15] = {kEvInquiryResultWithRssi, 15, 1};
  memcpy(rssi + 3, kPhone, 6);
  rssi[9] = 2;                                       // R2
  rssi[11] = 0x0C; rssi[12] = 0x02; rssi[13] = 0x5A; // CoD 0x5A020C
  rssi[14] = 0xCD; rssi[15] = 0xAB;                  // offset 0x2BCD after mask
  rssi[16] = (u8)-70;
  Feed(s, rssi, ++now);

  assert(r.found == 2 && s.device_count() == 2);
  assert(!strcmp(r.found_names[0], "Bose NC 700 HP"));
  const Device& d0 = s.devices()[0];
  assert(d0.class_of_device == 0x240404 && d0.rssi == -52 && d0.has_rssi);
  assert(d0.name_source == kNameEir);
  const Device& d1 = s.devices()[1];
  assert(d1.class_of_device == 0x5A020C && d1.rssi == -70);
  assert(d1.clock_offset == 0x2BCD && d1.page_scan_repetition_mode == 2);

  const u8 complete[] = {kEvInquiryComplete, 1, 0};
  Feed(s, complete, ++now);
  assert(s.stage() == kStageNames);

  // Only the unnamed device gets a Remote Name Request.
  const u8 name_req[] = {0x19, 0x04, 0x0A, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
                         0x02, 0x00, 0xCD, 0xAB};
  ExpectCommand(s, name_req, sizeof(name_req), now);
  CommandStatus(s, kOpRemoteNameRequest, 0, ++now);
  u8 name_event[2 + 255];
  memset(name_event, 0, sizeof(name_event));
  name_event[0] = kEvRemoteNameRequestComplete; name_event[1] = 255;
  name_event[2] = 0;
  memcpy(name_event + 3, kPhone, 6);
  memcpy(name_event + 9, "Pixel", 5);
  assert(r.completed == 0);
  Feed(s, name_event, ++now);
  assert(r.named == 1 && !strcmp(s.devices()[1].name, "Pixel"));
  assert(s.stage() == kStageDone && r.completed == 1 && r.complete_count == 2);
  assert(r.failed == 0 && r.warnings == 0);

  // A rescan skips controller setup and goes straight to Inquiry.
  assert(s.Rescan(now));
  assert(!s.Rescan(now));
  assert(s.stage() == kStageInquiry && s.device_count() == 0);
  assert(!memcmp(s.local_address(), kLocal, 6));
  ExpectCommand(s, inquiry, sizeof(inquiry), now);
  CommandStatus(s, kOpInquiry, 0, ++now);
  Feed(s, complete, ++now);
  assert(s.stage() == kStageDone && r.completed == 2 && r.complete_count == 0);
}

void TestSetupWithoutInquiry() {
  Recorder r;
  Scanner s(&r);
  unsigned now = 100;
  RunSetup(s, r, &now, false);
  // Controller configured, but no Inquiry until the Guide asks for one.
  assert(s.stage() == kStageDone && s.inquiries() == 0);
  u8 out[64];
  assert(s.NextCommand(out, sizeof(out)) == 0);
  s.Tick(now + 60000);
  assert(s.stage() == kStageDone && r.failed == 0 && r.completed == 0);
  assert(s.Rescan(now));
  assert(s.stage() == kStageInquiry && s.inquiries() == 1);
  const u8 inquiry[] = {0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x08, 0x00};
  ExpectCommand(s, inquiry, sizeof(inquiry), now);
}

void TestCommandTimeout() {
  Recorder r;
  Scanner s(&r);
  s.Start(100);
  u8 out[kMaxCommandBytes];
  assert(s.NextCommand(out, sizeof(out)) == 3);
  s.CommandSent(100);
  s.Tick(100 + Scanner::kCommandTimeoutMs - 1);
  assert(r.failed == 0);
  // A Command Complete for an unrelated opcode does not satisfy Reset.
  const u8 ok[] = {0};
  CommandComplete(s, kOpReadBdAddr, ok, 1, 200);
  assert(s.stage() == kStageReset && s.unhandled_events() == 1);
  s.Tick(100 + Scanner::kCommandTimeoutMs);
  assert(r.failed == 1 && r.fail_reason == kFailCommandTimeout);
  assert(r.fail_stage == kStageReset && r.fail_opcode == kOpReset);
  assert(s.finished() && s.NextCommand(out, sizeof(out)) == 0);
}

void TestResetRejectedAndHardwareError() {
  Recorder r;
  Scanner s(&r);
  s.Start(0);
  u8 out[kMaxCommandBytes];
  s.NextCommand(out, sizeof(out));
  s.CommandSent(0);
  const u8 err[] = {0x0C};
  CommandComplete(s, kOpReset, err, 1, 1);
  assert(r.failed == 1 && r.fail_reason == kFailCommandStatus && r.fail_status == 0x0C);

  Recorder r2;
  Scanner s2(&r2);
  s2.Start(0);
  const u8 hw[] = {kEvHardwareError, 1, 0x42};
  Feed(s2, hw, 1);
  assert(r2.failed == 1 && r2.fail_reason == kFailHardware && r2.fail_status == 0x42);
}

void TestInquiryModeFallbackAndFailures() {
  Recorder r;
  Scanner s(&r);
  unsigned now = 10;
  const u8 ok[] = {0};
  s.Start(now);
  u8 out[kMaxCommandBytes];
  // Reset, version (rejected: warning only), address, mask.
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandComplete(s, kOpReset, ok, 1, ++now);
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  const u8 unknown[] = {0x01};
  CommandComplete(s, kOpReadLocalVersion, unknown, 1, ++now);
  assert(r.warnings == 1 && r.versions == 0);
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  u8 addr_ret[7] = {0};
  CommandComplete(s, kOpReadBdAddr, addr_ret, 7, ++now);
  // Read_Buffer_Size rejected: a warning; defaults stay.
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandComplete(s, kOpReadBufferSize, unknown, 1, ++now);
  assert(r.warnings == 2 && s.acl_mtu() == 27 && s.acl_buffers() == 1);
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandComplete(s, kOpSetEventMask, ok, 1, ++now);

  // Extended mode rejected -> retries mode 1 -> rejected -> inquiry anyway.
  const u8 mode2[] = {0x45, 0x0C, 0x01, 0x02};
  ExpectCommand(s, mode2, 4, now);
  CommandComplete(s, kOpWriteInquiryMode, unknown, 1, ++now);
  const u8 mode1[] = {0x45, 0x0C, 0x01, 0x01};
  ExpectCommand(s, mode1, 4, now);
  CommandComplete(s, kOpWriteInquiryMode, unknown, 1, ++now);
  assert(s.stage() == kStageSimplePairing && r.warnings == 4);
  // SSP and local name failures are warnings too.
  SetupTail(s, &now, 0x01, 0x01);
  assert(s.stage() == kStageInquiry && r.warnings == 6);

  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandStatus(s, kOpInquiry, 0, ++now);
  // Standard Inquiry Result (no RSSI, no name).
  u8 result[2 + 15] = {kEvInquiryResult, 15, 1};
  memcpy(result + 3, kBose, 6);
  result[9] = 1;
  result[12] = 0x04; result[13] = 0x04; result[14] = 0x24;
  Feed(s, result, ++now);
  assert(s.device_count() == 1 && !s.devices()[0].has_rssi);
  assert(s.devices()[0].class_of_device == 0x240404);
  // Inquiry never completes -> inquiry timeout.
  s.Tick(now + 8 * 1280 + 5000);
  assert(r.failed == 1 && r.fail_reason == kFailInquiryTimeout);
}

void TestNameFailures() {
  Recorder r;
  Scanner s(&r);
  unsigned now = 0;
  RunSetup(s, r, &now);
  u8 out[kMaxCommandBytes];
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandStatus(s, kOpInquiry, 0, ++now);
  u8 rssi[2 + 15] = {kEvInquiryResultWithRssi, 15, 1};
  memcpy(rssi + 3, kBose, 6);
  Feed(s, rssi, ++now);
  memcpy(rssi + 3, kPhone, 6);
  Feed(s, rssi, ++now);
  const u8 complete[] = {kEvInquiryComplete, 1, 0};
  Feed(s, complete, ++now);

  // First name request: page timeout reported in the completion event.
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandStatus(s, kOpRemoteNameRequest, 0, ++now);
  u8 fail_event[2 + 7] = {kEvRemoteNameRequestComplete, 7, 0x04};
  memcpy(fail_event + 3, kBose, 6);
  Feed(s, fail_event, ++now);
  assert(r.warnings == 1 && r.warn_status == 0x04);
  assert(s.devices()[0].name_source == kNameFailed);
  // Second: no completion at all -> scan finishes with a warning.
  assert(s.stage() == kStageNames);
  s.NextCommand(out, sizeof(out)); s.CommandSent(now);
  CommandStatus(s, kOpRemoteNameRequest, 0, ++now);
  s.Tick(now + Scanner::kNameTimeoutMs);
  assert(r.warnings == 2 && r.completed == 1 && r.failed == 0);
  assert(s.stage() == kStageDone);
}

void TestRing() {
  ByteRing<16> ring;
  u8 in[12], out[16];
  for (unsigned i = 0; i < sizeof(in); ++i) in[i] = (u8)(i + 1);
  assert(ring.Write(in, 12));
  assert(!ring.Write(in, 5) && ring.dropped() == 1);  // All-or-nothing.
  assert(ring.Read(out, 8) == 8 && out[0] == 1 && out[7] == 8);
  assert(ring.Write(in, 12));                          // Wraps.
  assert(ring.Read(out, 16) == 16);
  assert(out[0] == 9 && out[3] == 12 && out[4] == 1 && out[15] == 12);
  assert(ring.Read(out, 16) == 0);
  assert(ring.Write(in, 3));
  ring.Clear();
  assert(ring.Read(out, 16) == 0);
}

}  // namespace

int main() {
  TestDescriptors();
  TestAssembler();
  TestNames();
  TestFullScan();
  TestSetupWithoutInquiry();
  TestCommandTimeout();
  TestResetRejectedAndHardwareError();
  TestInquiryModeFallbackAndFailures();
  TestNameFailures();
  TestRing();
  puts("Bluetooth HCI tests passed");
  return 0;
}
