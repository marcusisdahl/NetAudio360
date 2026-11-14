// SPDX-License-Identifier: GPL-3.0-or-later
// Host tests for bt::Link: pairing, reconnect with a stored key, failures.
#include "../src/bt_link.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

using namespace bt;

namespace {

const u8 kBose[6] = {0x06, 0x2D, 0x5B, 0x23, 0x7B, 0xC8};
const u8 kKey[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

struct Recorder : LinkObserver {
  Recorder() : has_key(false), key_type(0), keys(0), rejected(0), states(0),
               failed(0), last_state(0), fail(0), fail_opcode(0),
               fail_status(0) {
    memset(stored, 0, sizeof(stored));
  }
  bool FindLinkKey(const u8* address, u8* key) {
    if (!has_key || memcmp(address, kBose, 6)) return false;
    memcpy(key, stored, 16);
    return true;
  }
  void OnLinkKey(const u8*, const u8* key, u8 type) {
    memcpy(stored, key, 16); has_key = true; key_type = type; ++keys;
  }
  void OnLinkKeyRejected(const u8*) { has_key = false; ++rejected; }
  void OnLinkState(unsigned state, const u8*) { last_state = state; ++states; }
  void OnLinkFailed(unsigned failure, u16 opcode, u8 status, const u8*) {
    ++failed; fail = failure; fail_opcode = opcode; fail_status = status;
  }
  bool has_key;
  u8 stored[16];
  u8 key_type;
  int keys, rejected, states, failed;
  unsigned last_state, fail;
  u16 fail_opcode;
  u8 fail_status;
};

void Feed(Link& l, const u8* e, unsigned now) { l.OnEvent(e, 2u + e[1], now); }

// Sends the next command, checks opcode and returns its parameters.
const u8* Expect(Link& l, u16 opcode, unsigned plen, unsigned now) {
  static u8 out[kMaxCommandBytes];
  unsigned n = l.NextCommand(out, sizeof(out));
  if (n != 3 + plen || out[0] != (u8)opcode || out[1] != (u8)(opcode >> 8)) {
    fprintf(stderr, "expected %04x/%u got n=%u %02x%02x\n", opcode, plen, n,
            out[1], out[0]);
    assert(false);
  }
  l.CommandSent(now);
  assert(l.NextCommand(out, sizeof(out)) == 0);  // One in flight.
  return out + 3;
}

void Status(Link& l, u16 opcode, u8 status, unsigned now) {
  u8 e[6] = {kEvCommandStatus, 4, status, 1, (u8)opcode, (u8)(opcode >> 8)};
  Feed(l, e, now);
}

void Complete(Link& l, u16 opcode, unsigned now) {
  u8 e[12] = {kEvCommandComplete, 10, 1, (u8)opcode, (u8)(opcode >> 8), 0};
  memcpy(e + 6, kBose, 6);
  Feed(l, e, now);
}

void AddressEvent(Link& l, u8 code, unsigned now) {
  u8 e[8] = {code, 6};
  memcpy(e + 2, kBose, 6);
  Feed(l, e, now);
}

void Connected(Link& l, u8 status, unsigned now) {
  u8 e[13] = {kEvConnectionComplete, 11, status, 0x2A, 0x00};
  memcpy(e + 5, kBose, 6);
  e[11] = 1;  // ACL
  e[12] = 0;
  Feed(l, e, now);
}

void AuthComplete(Link& l, u8 status, unsigned now) {
  u8 e[5] = {kEvAuthenticationComplete, 3, status, 0x2A, 0x00};
  Feed(l, e, now);
}

void Encrypted(Link& l, u8 status, u8 on, unsigned now) {
  u8 e[6] = {kEvEncryptionChange, 4, status, 0x2A, 0x00, on};
  Feed(l, e, now);
}

void Disconnected(Link& l, u8 reason, unsigned now) {
  u8 e[6] = {kEvDisconnectionComplete, 4, 0, 0x2A, 0x00, reason};
  Feed(l, e, now);
}

Device Bose() {
  Device d;
  memset(&d, 0, sizeof(d));
  memcpy(d.address, kBose, 6);
  d.page_scan_repetition_mode = 1;
  d.clock_offset = 0x1234;
  return d;
}

void ConnectAndAuthStart(Link& l, unsigned* now) {
  assert(l.Connect(Bose(), *now));
  assert(l.state() == kLinkConnecting);
  const u8* p = Expect(l, kOpCreateConnection, 13, *now);
  assert(!memcmp(p, kBose, 6));
  assert(p[6] == 0x18 && p[7] == 0xCC && p[8] == 1);
  assert(p[10] == 0x34 && p[11] == 0x92 && p[12] == 1);  // 0x1234 | 0x8000
  Status(l, kOpCreateConnection, 0, ++*now);
  Connected(l, 0, ++*now);
  assert(l.state() == kLinkAuthenticating && l.handle() == 0x2A);
  p = Expect(l, kOpAuthenticationRequested, 2, *now);
  assert(p[0] == 0x2A && p[1] == 0);
  Status(l, kOpAuthenticationRequested, 0, ++*now);
}

void FinishEncryption(Link& l, unsigned* now) {
  const u8* p = Expect(l, kOpSetConnectionEncryption, 3, *now);
  assert(p[0] == 0x2A && p[2] == 1);
  Status(l, kOpSetConnectionEncryption, 0, ++*now);
  Encrypted(l, 0, 1, ++*now);
  assert(l.state() == kLinkConnected);
}

void TestSimplePairing() {
  Recorder r;
  Link l(&r);
  unsigned now = 0xFFFFFFF0u;  // Wraps during the test.
  ConnectAndAuthStart(l, &now);

  AddressEvent(l, kEvLinkKeyRequest, ++now);
  Expect(l, kOpLinkKeyRequestNegativeReply, 6, now);
  Complete(l, kOpLinkKeyRequestNegativeReply, ++now);

  AddressEvent(l, kEvIoCapabilityRequest, ++now);
  const u8* p = Expect(l, kOpIoCapabilityRequestReply, 9, now);
  assert(!memcmp(p, kBose, 6) && p[6] == 3 && p[7] == 0 && p[8] == 2);
  Complete(l, kOpIoCapabilityRequestReply, ++now);

  u8 io[11] = {kEvIoCapabilityResponse, 9};
  memcpy(io + 2, kBose, 6);
  io[8] = 3;
  Feed(l, io, ++now);

  u8 confirm[12] = {kEvUserConfirmationRequest, 10};
  memcpy(confirm + 2, kBose, 6);
  Feed(l, confirm, ++now);
  Expect(l, kOpUserConfirmationRequestReply, 6, now);
  Complete(l, kOpUserConfirmationRequestReply, ++now);

  u8 spc[9] = {kEvSimplePairingComplete, 7, 0};
  memcpy(spc + 3, kBose, 6);
  Feed(l, spc, ++now);

  u8 note[25] = {kEvLinkKeyNotification, 23};
  memcpy(note + 2, kBose, 6);
  memcpy(note + 8, kKey, 16);
  note[24] = 4;  // Unauthenticated combination key (P-192).
  Feed(l, note, ++now);
  assert(r.keys == 1 && r.key_type == 4 && !memcmp(r.stored, kKey, 16));
  assert(l.paired_now());

  AuthComplete(l, 0, ++now);
  assert(l.state() == kLinkEncrypting);
  FinishEncryption(l, &now);
  assert(r.failed == 0 && l.unhandled_events() == 0);

  // A clean disconnect.
  assert(l.Disconnect(now));
  p = Expect(l, kOpDisconnect, 3, now);
  assert(p[0] == 0x2A && p[2] == 0x13);
  Status(l, kOpDisconnect, 0, ++now);
  Disconnected(l, 0x16, ++now);
  assert(l.state() == kLinkIdle && r.failed == 0);
}

void TestReconnectWithStoredKey() {
  Recorder r;
  r.has_key = true;
  memcpy(r.stored, kKey, 16);
  Link l(&r);
  unsigned now = 10;
  ConnectAndAuthStart(l, &now);
  AddressEvent(l, kEvLinkKeyRequest, ++now);
  const u8* p = Expect(l, kOpLinkKeyRequestReply, 22, now);
  assert(!memcmp(p, kBose, 6) && !memcmp(p + 6, kKey, 16));
  Complete(l, kOpLinkKeyRequestReply, ++now);
  AuthComplete(l, 0, ++now);
  FinishEncryption(l, &now);
  assert(!l.paired_now() && r.keys == 0 && r.rejected == 0);

  // The headphones turn off.
  Disconnected(l, 0x13, ++now);
  assert(l.state() == kLinkIdle && r.failed == 1 && r.fail == kLinkFailClosed &&
         r.fail_status == 0x13);
}

void TestStoredKeyRejected() {
  Recorder r;
  r.has_key = true;
  memcpy(r.stored, kKey, 16);
  Link l(&r);
  unsigned now = 10;
  ConnectAndAuthStart(l, &now);
  AddressEvent(l, kEvLinkKeyRequest, ++now);
  Expect(l, kOpLinkKeyRequestReply, 22, now);
  Complete(l, kOpLinkKeyRequestReply, ++now);
  AuthComplete(l, 0x06, ++now);  // Key missing on the remote.
  assert(r.rejected == 1 && !r.has_key);
  // The link is closed before the failure is reported.
  assert(l.state() == kLinkDisconnecting && r.failed == 0);
  Expect(l, kOpDisconnect, 3, now);
  Status(l, kOpDisconnect, 0, ++now);
  Disconnected(l, 0x16, ++now);
  assert(l.state() == kLinkIdle && r.failed == 1 && r.fail == kLinkFailAuth &&
         r.fail_status == 0x06);
}

void TestPageTimeoutAndLegacyPin() {
  Recorder r;
  Link l(&r);
  unsigned now = 10;
  assert(l.Connect(kBose, now));
  const u8* p = Expect(l, kOpCreateConnection, 13, now);
  assert(p[10] == 0 && p[11] == 0);  // No clock offset known.
  Status(l, kOpCreateConnection, 0, ++now);
  Connected(l, 0x04, ++now);  // Page timeout: headphones off.
  assert(l.state() == kLinkIdle && r.failed == 1 && r.fail == kLinkFailConnect &&
         r.fail_status == 0x04);

  // Controller without SSP on the remote: legacy PIN "0000".
  ConnectAndAuthStart(l, &now);
  AddressEvent(l, kEvLinkKeyRequest, ++now);
  Expect(l, kOpLinkKeyRequestNegativeReply, 6, now);
  Complete(l, kOpLinkKeyRequestNegativeReply, ++now);
  AddressEvent(l, kEvPinCodeRequest, ++now);
  p = Expect(l, kOpPinCodeRequestReply, 23, now);
  assert(p[6] == 4 && !memcmp(p + 7, "0000", 4) && p[11] == 0);
  Complete(l, kOpPinCodeRequestReply, ++now);
  AuthComplete(l, 0, ++now);
  FinishEncryption(l, &now);
}

void TestRejectedCommandAndTimeouts() {
  Recorder r;
  Link l(&r);
  unsigned now = 10;
  assert(l.Connect(kBose, now));
  assert(!l.Connect(kBose, now));  // Only one link at a time.
  Expect(l, kOpCreateConnection, 13, now);
  Status(l, kOpCreateConnection, 0x0B, ++now);  // Connection already exists.
  assert(l.state() == kLinkIdle && r.fail == kLinkFailCommand && r.fail_status == 0x0B);

  // No Command Status at all.
  assert(l.Connect(kBose, now));
  Expect(l, kOpCreateConnection, 13, now);
  l.Tick(now + Link::kCommandTimeoutMs);
  assert(l.state() == kLinkIdle && r.fail == kLinkFailTimeout);

  // Paging never completes.
  unsigned start = now;
  assert(l.Connect(kBose, now));
  Expect(l, kOpCreateConnection, 13, now);
  Status(l, kOpCreateConnection, 0, ++now);
  l.Tick(start + Link::kConnectTimeoutMs - 1);
  assert(l.state() == kLinkConnecting);
  l.Tick(start + Link::kConnectTimeoutMs);
  assert(l.state() == kLinkIdle && r.fail == kLinkFailTimeout);

  // Encryption refused: closed, then reported.
  r.failed = 0;
  ConnectAndAuthStart(l, &now);
  AuthComplete(l, 0, ++now);
  Expect(l, kOpSetConnectionEncryption, 3, now);
  Status(l, kOpSetConnectionEncryption, 0, ++now);
  Encrypted(l, 0, 0, ++now);
  assert(l.state() == kLinkDisconnecting);
  Expect(l, kOpDisconnect, 3, now);
  Status(l, kOpDisconnect, 0x02, ++now);  // Already gone.
  assert(l.state() == kLinkIdle && r.failed == 1 && r.fail == kLinkFailEncrypt);

  // Events for another device are ignored.
  ConnectAndAuthStart(l, &now);
  u8 other[8] = {kEvIoCapabilityRequest, 6, 9, 9, 9, 9, 9, 9};
  Feed(l, other, ++now);
  u8 out[kMaxCommandBytes];
  assert(l.NextCommand(out, sizeof(out)) == 0 && l.unhandled_events() == 1);
}

void TestAbandonWhilePaging() {
  Recorder r;
  Link l(&r);
  unsigned now = 10;
  assert(l.Connect(kBose, now));
  Expect(l, kOpCreateConnection, 13, now);
  Status(l, kOpCreateConnection, 0, ++now);
  assert(l.Disconnect(now));
  assert(l.state() == kLinkIdle);
  // The connection completes anyway: it is closed straight away.
  Connected(l, 0, ++now);
  const u8* p = Expect(l, kOpDisconnect, 3, now);
  assert(p[0] == 0x2A);
}

void TestPairedStore() {
  PairedStore store;
  const u8 a1[6] = {1, 2, 3, 4, 5, 6};
  const u8 a2[6] = {7, 8, 9, 10, 11, 12};
  const u8 a3[6] = {13, 14, 15, 16, 17, 18};
  store.Put(kBose, kKey, 4, "Bose NC 700 Headphones");
  store.Put(a1, kKey, 5, "Phone\twith tab");
  assert(store.count() == 2 && !memcmp(store.at(0).address, a1, 6));
  assert(!strcmp(store.at(0).name, "Phone with tab"));
  // Re-pairing keeps the name when none is given and moves it to the front.
  u8 key2[16];
  memset(key2, 0xAB, 16);
  store.Put(kBose, key2, 7, 0);
  assert(store.count() == 2 && !memcmp(store.at(0).address, kBose, 6));
  assert(!strcmp(store.at(0).name, "Bose NC 700 Headphones"));
  assert(store.at(0).key_type == 7 && !memcmp(store.at(0).key, key2, 16));

  char text[512];
  unsigned n = store.Format(text, sizeof(text));
  assert(n && n == strlen(text));
  assert(strstr(text, "C8:7B:23:5B:2D:06 abababababababababababababababab 7 "
                      "Bose NC 700 Headphones\r\n"));
  assert(store.Format(text, 40) == 0);

  PairedStore loaded;
  assert(loaded.Parse(text, n));
  assert(loaded.count() == 2);
  assert(!memcmp(loaded.at(0).address, kBose, 6) &&
         !memcmp(loaded.at(0).key, key2, 16) && loaded.at(0).key_type == 7);
  assert(!strcmp(loaded.at(1).name, "Phone with tab") &&
         loaded.at(1).key_type == 5);
  const PairedDevice* found = loaded.Find(a1);
  assert(found && found == &loaded.at(1));

  // Oldest dropped when full; Remove.
  loaded.Put(a2, kKey, 4, "Two");
  loaded.Put(a3, kKey, 4, "Three");
  assert(loaded.count() == kMaxPaired && !loaded.Find(a1));
  assert(loaded.Remove(a2) && !loaded.Remove(a2) && loaded.count() == 2);

  // Malformed input keeps the previous contents.
  const char bad[] = "C8:7B:23:5B:2D:06 not-a-key 4 x\n";
  assert(!loaded.Parse(bad, sizeof(bad) - 1) && loaded.count() == 2);
  const char lf[] = "# c\n\nC8:7B:23:5B:2D:06 0102030405060708090a0b0c0d0e0f10 4\n";
  assert(loaded.Parse(lf, sizeof(lf) - 1) && loaded.count() == 1);
  assert(!memcmp(loaded.at(0).key, kKey, 16) && loaded.at(0).name[0] == 0);
  const char empty[] = "";
  assert(loaded.Parse(empty, 0) && loaded.count() == 0);
}

}  // namespace

int main() {
  TestPairedStore();
  TestSimplePairing();
  TestReconnectWithStoredKey();
  TestStoredKeyRejected();
  TestPageTimeoutAndLegacyPin();
  TestRejectedCommandAndTimeouts();
  TestAbandonWhilePaging();
  printf("Bluetooth link tests passed\n");
  return 0;
}
