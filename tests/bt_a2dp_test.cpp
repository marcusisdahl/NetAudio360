// SPDX-License-Identifier: GPL-3.0-or-later
// Host tests for the SBC encoder framing, ACL reassembly and the A2DP source
// state machine against a scripted sink.
#include "../src/bt_a2dp.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

using namespace bt;

namespace {

u16 Le16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }

struct Recorder : A2dpObserver {
  Recorder() : states(0), last_state(0), failed(0), failure(0), detail(0),
               configured(0), keys(0), last_key(0) {
    memset(&config, 0, sizeof(config));
  }
  void OnA2dpState(unsigned s) { ++states; last_state = s; }
  void OnA2dpFailed(unsigned f, unsigned d) { ++failed; failure = f; detail = d; }
  void OnA2dpConfigured(const SbcConfig& c) { ++configured; config = c; }
  void OnAvrcpKey(unsigned op) { ++keys; last_key = op; }
  int states;
  unsigned last_state;
  int failed;
  unsigned failure, detail;
  int configured;
  SbcConfig config;
  unsigned keys, last_key;
};

// Pops one output frame; checks the CID and returns the payload.
const u8* Pop(A2dpSource& a, u16 cid, unsigned* n) {
  static u8 copy[1200];
  unsigned length = 0;
  const u8* f = a.Output(&length);
  assert(f && length >= 4);
  assert(Le16(f) == length - 4);
  if (Le16(f + 2) != cid) {
    fprintf(stderr, "cid %04x expected %04x\n", Le16(f + 2), cid);
    assert(false);
  }
  memcpy(copy, f + 4, length - 4);
  *n = length - 4;
  a.PopOutput();
  return copy;
}

void Frame(A2dpSource& a, u16 cid, const u8* payload, unsigned n, unsigned now) {
  u8 f[1200];
  f[0] = (u8)n; f[1] = (u8)(n >> 8); f[2] = (u8)cid; f[3] = (u8)(cid >> 8);
  memcpy(f + 4, payload, n);
  a.OnFrame(f, 4 + n, now);
}

void Signal(A2dpSource& a, u8 code, u8 id, const u8* d, unsigned n, unsigned now) {
  u8 p[64] = {code, id, (u8)n, 0};
  memcpy(p + 4, d, n);
  Frame(a, 0x0001, p, 4 + n, now);
}

// Expects a signalling command with the given code; returns its data.
const u8* ExpectSignal(A2dpSource& a, u8 code, u8* id, unsigned* n) {
  unsigned len = 0;
  const u8* p = Pop(a, 0x0001, &len);
  assert(len >= 4 && p[0] == code);
  *id = p[1];
  *n = Le16(p + 2);
  return p + 4;
}

void OpenChannel(A2dpSource& a, u16 our_cid, u16 their_cid, unsigned now) {
  u8 id; unsigned n;
  const u8* d = ExpectSignal(a, 0x02, &id, &n);  // Connection Request
  assert(n == 4 && Le16(d) == 0x0019 && Le16(d + 2) == our_cid);
  u8 rsp[8] = {(u8)their_cid, (u8)(their_cid >> 8), (u8)our_cid, 0, 1, 0, 0, 0};
  Signal(a, 0x03, id, rsp, 8, now);  // Pending first.
  assert(!a.HasOutput());
  rsp[4] = 0;
  Signal(a, 0x03, id, rsp, 8, now);
  d = ExpectSignal(a, 0x04, &id, &n);  // Our Configure Request.
  assert(n == 8 && Le16(d) == their_cid && d[4] == 1 && Le16(d + 6) == 1000);
  u8 cfg_rsp[6] = {(u8)our_cid, 0, 0, 0, 0, 0};
  Signal(a, 0x05, id, cfg_rsp, 6, now);
  // Their Configure Request with MTU 895.
  u8 cfg[8] = {(u8)our_cid, 0, 0, 0, 0x01, 2, 0x7F, 0x03};
  Signal(a, 0x04, 9, cfg, 8, now);
  d = ExpectSignal(a, 0x05, &id, &n);
  assert(id == 9 && Le16(d) == their_cid && Le16(d + 4) == 0);
}

// Expects an AVDTP command on the signalling channel; returns the label.
u8 ExpectAvdtp(A2dpSource& a, u8 signal, const u8** data, unsigned* n) {
  unsigned len = 0;
  const u8* p = Pop(a, 0x0050, &len);
  assert(len >= 2 && (p[0] & 0x0F) == 0 && p[1] == signal);
  *data = p + 2;
  *n = len - 2;
  return (u8)(p[0] >> 4);
}

void Accept(A2dpSource& a, u8 label, u8 signal, const u8* d, unsigned n,
            unsigned now) {
  u8 p[64] = {(u8)((label << 4) | 2), signal};
  if (n) memcpy(p + 2, d, n);
  Frame(a, 0x0040, p, 2 + n, now);
}

void TestSbcFraming() {
  SbcEncoder e;
  SbcConfig c = {kSbc48k, 16, kSbcJoint, kSbcLoudness, 53};
  assert(e.Configure(c));
  assert(e.frame_length() == 119 && e.samples_per_frame() == 128);
  short pcm[256];
  for (int i = 0; i < 128; ++i) {
    pcm[2 * i] = (short)(10000 * sin(i * 0.1));
    pcm[2 * i + 1] = (short)(8000 * sin(i * 0.05));
  }
  u8 frame[512];
  assert(e.Encode(pcm, frame) == 119);
  assert(frame[0] == 0x9C && frame[1] == 0xFD && frame[2] == 53);
  SbcConfig bad = c;
  bad.bitpool = 300;
  assert(!e.Configure(bad));
  bad = c; bad.blocks = 5;
  assert(!e.Configure(bad));
}

void TestAclAssembler() {
  AclAssembler acl;
  // One L2CAP frame (len 6, cid 0x40) split over two ACL fragments, the
  // bytes pushed in odd-sized chunks.
  const u8 stream[] = {0x2A, 0x20, 5, 0, 6, 0, 0x40, 0, 0xAA,
                       0x2A, 0x10, 5, 0, 1, 2, 3, 4, 5};
  bool complete = false;
  unsigned used = 0, frames = 0;
  while (used < sizeof(stream)) {
    unsigned chunk = sizeof(stream) - used < 3 ? sizeof(stream) - used : 3;
    unsigned at = 0;
    while (at < chunk) {
      at += acl.Push(stream + used + at, chunk - at, &complete);
      if (complete) {
        ++frames;
        assert(acl.handle() == 0x02A && acl.frame_length() == 10);
        assert(acl.frame()[4] == 0xAA && acl.frame()[9] == 5);
      }
    }
    used += chunk;
  }
  assert(frames == 1);
}

void TestStreamSetup() {
  Recorder r;
  A2dpSource a(&r);
  unsigned now = 1000;
  assert(a.Start(now));
  assert(!a.Start(now));
  OpenChannel(a, 0x0040, 0x0050, now);
  // Discover: one source SEP (ignored), one in-use sink, one free sink.
  const u8* d; unsigned n;
  u8 label = ExpectAvdtp(a, 0x01, &d, &n);
  const u8 seps[] = {0x04, 0x00, 0x0A, 0x08, 0x0C, 0x08};
  Accept(a, label, 0x01, seps, sizeof(seps), now);
  label = ExpectAvdtp(a, 0x02, &d, &n);
  assert(n == 1 && d[0] == (3 << 2));
  // Capabilities: transport, SBC with all options, bitpool 2..53, delay report.
  const u8 caps[] = {0x01, 0, 0x07, 6, 0x00, 0x00, 0xFF, 0xFF, 2, 53, 0x08, 0};
  Accept(a, label, 0x02, caps, sizeof(caps), now);
  label = ExpectAvdtp(a, 0x03, &d, &n);
  const u8 set[] = {3 << 2, 1 << 2, 0x01, 0, 0x07, 6, 0x00, 0x00, 0x11, 0x15, 53, 53};
  assert(n == sizeof(set) && !memcmp(d, set, n));
  Accept(a, label, 0x03, 0, 0, now);
  assert(r.configured == 1 && r.config.frequency == kSbc48k &&
         r.config.channel_mode == kSbcJoint && r.config.bitpool == 53);
  label = ExpectAvdtp(a, 0x06, &d, &n);
  Accept(a, label, 0x06, 0, 0, now);
  assert(a.state() == kA2dpMediaConnect);
  OpenChannel(a, 0x0041, 0x0051, now);
  label = ExpectAvdtp(a, 0x07, &d, &n);
  assert(d[0] == (3 << 2));
  Accept(a, label, 0x07, 0, 0, now);
  assert(a.streaming() && a.media_mtu() == 0x037F && r.failed == 0);

  // A media packet.
  u8 frames[238];
  memset(frames, 0x5A, sizeof(frames));
  assert(a.SendMedia(frames, sizeof(frames), 2, 256));
  const u8* m = Pop(a, 0x0051, &n);
  assert(n == 12 + 1 + 238 && m[0] == 0x80 && m[1] == 0x60 && m[12] == 2);
  assert(m[7] == 0 && m[6] == 1);  // Timestamp 256, big-endian.

  // The headphones pause and resume; then an info request and echo.
  u8 suspend[3] = {0x50, 0x09, 3 << 2};
  Frame(a, 0x0040, suspend, 3, now);
  m = Pop(a, 0x0050, &n);
  assert(n == 2 && m[0] == 0x52 && m[1] == 0x09 && a.state() == kA2dpSuspended);
  assert(!a.SendMedia(frames, 10, 1, 0));
  u8 start[3] = {0x60, 0x07, 3 << 2};
  Frame(a, 0x0040, start, 3, now);
  m = Pop(a, 0x0050, &n);
  assert(m[0] == 0x62 && a.streaming());
  u8 info[2] = {0x02, 0x00};
  Signal(a, 0x0A, 7, info, 2, now);
  u8 id;
  d = ExpectSignal(a, 0x0B, &id, &n);
  assert(id == 7 && n == 8 && Le16(d) == 2 && Le16(d + 2) == 0);
  // The headphones open AVRCP: accepted, and their volume keys reach us.
  u8 avrcp[4] = {0x17, 0x00, 0x60, 0x00};
  Signal(a, 0x02, 8, avrcp, 4, now);
  d = ExpectSignal(a, 0x03, &id, &n);
  assert(Le16(d) == 0x43 && Le16(d + 2) == 0x60 && Le16(d + 4) == 0);
  d = ExpectSignal(a, 0x04, &id, &n);
  assert(Le16(d) == 0x60);
  u8 key[8] = {0x30, 0x11, 0x0E, 0x00, 0x48, 0x7C, 0x42, 0x00};
  Frame(a, 0x0043, key, 8, now);
  m = Pop(a, 0x0060, &n);
  assert(n == 8 && m[0] == 0x32 && m[3] == 0x09 && r.keys == 1 && r.last_key == 0x42);

  // Remote closes the media channel.
  u8 disc[4] = {0x41, 0x00, 0x51, 0x00};
  Signal(a, 0x06, 11, disc, 4, now);
  d = ExpectSignal(a, 0x07, &id, &n);
  assert(a.state() == kA2dpFailed && r.failure == kA2dpFailClosed);
}

void TestFailures() {
  Recorder r;
  A2dpSource a(&r);
  unsigned now = 0;
  assert(a.Start(now));
  u8 id; unsigned n;
  ExpectSignal(a, 0x02, &id, &n);
  u8 refused[8] = {0, 0, 0x40, 0, 3, 0, 0, 0};  // Security block.
  Signal(a, 0x03, id, refused, 8, now);
  assert(a.state() == kA2dpFailed && r.failure == kA2dpFailL2cap && r.detail == 3);

  // No reply at all.
  a.Reset();
  r.failed = 0;
  assert(a.Start(now));
  a.Tick(now + A2dpSource::kStepTimeoutMs - 1);
  assert(a.state() == kA2dpSignalConnect);
  a.Tick(now + A2dpSource::kStepTimeoutMs);
  assert(a.state() == kA2dpFailed && r.failure == kA2dpFailTimeout);

  // A sink without 48 kHz.
  a.Reset();
  assert(a.Start(now));
  OpenChannel(a, 0x0040, 0x0050, now);
  const u8* d;
  u8 label = ExpectAvdtp(a, 0x01, &d, &n);
  const u8 seps[] = {0x04, 0x08};
  Accept(a, label, 0x01, seps, sizeof(seps), now);
  label = ExpectAvdtp(a, 0x02, &d, &n);
  const u8 caps[] = {0x01, 0, 0x07, 6, 0x00, 0x00, 0x2F, 0xFF, 2, 53};
  Accept(a, label, 0x02, caps, sizeof(caps), now);
  assert(a.state() == kA2dpFailed && r.failure == kA2dpFailNoSbcSink);
}

}  // namespace

int main() {
  TestSbcFraming();
  TestAclAssembler();
  TestStreamSetup();
  TestFailures();
  printf("Bluetooth A2DP tests passed\n");
  return 0;
}
