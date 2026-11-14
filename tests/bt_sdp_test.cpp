// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/bt_sdp.h"

using namespace bt;

namespace {

unsigned SearchAttribute(const u8* pattern, unsigned pattern_length,
                         unsigned max_bytes, const u8* cont, unsigned cont_length,
                         u8* out, unsigned capacity) {
  u8 req[64];
  unsigned at = 5;
  req[0] = 0x06; req[1] = 0x12; req[2] = 0x34;
  req[at++] = 0x35; req[at++] = (u8)pattern_length;
  memcpy(req + at, pattern, pattern_length); at += pattern_length;
  req[at++] = (u8)(max_bytes >> 8); req[at++] = (u8)max_bytes;
  const u8 ids[] = {0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF};
  memcpy(req + at, ids, sizeof(ids)); at += sizeof(ids);
  memcpy(req + at, cont, cont_length); at += cont_length;
  req[3] = (u8)((at - 5) >> 8); req[4] = (u8)(at - 5);
  return SdpHandle(req, at, out, capacity);
}

bool Contains(const u8* p, unsigned n, const u8* needle, unsigned m) {
  for (unsigned i = 0; i + m <= n; ++i) if (!memcmp(p + i, needle, m)) return true;
  return false;
}

}  // namespace

int main() {
  u8 out[700];
  const u8 source[] = {0x19, 0x11, 0x0A};
  const u8 zero[] = {0};
  unsigned n = SearchAttribute(source, sizeof(source), 0xFFFF, zero, 1, out, sizeof(out));
  assert(n > 10 && out[0] == 0x07 && out[1] == 0x12 && out[2] == 0x34);
  assert((unsigned)((out[3] << 8) | out[4]) == n - 5);
  unsigned lists = (out[5] << 8) | out[6];
  assert(7 + lists + 1 == n && out[n - 1] == 0);
  assert(out[7] == 0x36 && out[10] == 0x36);
  const u8 psm[] = {0x19, 0x01, 0x00, 0x09, 0x00, 0x19};
  const u8 profile[] = {0x19, 0x11, 0x0D, 0x09, 0x01, 0x03};
  assert(Contains(out, n, psm, sizeof(psm)));
  assert(Contains(out, n, profile, sizeof(profile)));
  u8 full[700];
  memcpy(full, out + 7, lists);

  // Continuation: small MaximumAttributeByteCount, reassembled.
  u8 joined[700];
  unsigned have = 0;
  u8 cont[3] = {0};
  unsigned cont_length = 1;
  for (int round = 0; round < 50; ++round) {
    n = SearchAttribute(source, sizeof(source), 16, cont, cont_length, out, sizeof(out));
    assert(n && out[0] == 0x07);
    unsigned chunk = (out[5] << 8) | out[6];
    assert(chunk <= 16);
    memcpy(joined + have, out + 7, chunk);
    have += chunk;
    unsigned state = out[7 + chunk];
    if (!state) break;
    assert(state == 2);
    memcpy(cont, out + 7 + chunk, 3);
    cont_length = 3;
  }
  assert(have == lists && !memcmp(joined, full, lists));

  // 128-bit base UUID form of AudioSource matches too.
  const u8 source128[] = {0x1C, 0x00, 0x00, 0x11, 0x0A, 0x00, 0x00, 0x10, 0x00,
                          0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};
  n = SearchAttribute(source128, sizeof(source128), 0xFFFF, zero, 1, out, sizeof(out));
  assert((unsigned)((out[5] << 8) | out[6]) == lists);

  // A service we do not offer: an empty sequence of lists.
  const u8 headset[] = {0x19, 0x11, 0x08};
  n = SearchAttribute(headset, sizeof(headset), 0xFFFF, zero, 1, out, sizeof(out));
  assert(n == 11 && out[5] == 0 && out[6] == 3 && out[7] == 0x36 && out[8] == 0 &&
         out[9] == 0 && out[10] == 0);

  // ServiceSearch, then ServiceAttribute on the returned handle.
  const u8 search[] = {0x02, 0x00, 0x01, 0x00, 0x08, 0x35, 0x03, 0x19, 0x11, 0x0A,
                       0x00, 0x05, 0x00};
  n = SdpHandle(search, sizeof(search), out, sizeof(out));
  assert(n == 14 && out[0] == 0x03 && out[6] == 1 && out[8] == 1);
  assert(out[9] == 0 && out[10] == 1 && out[11] == 0 && out[12] == 1 && out[13] == 0);
  // L2CAP is in all three records.
  const u8 search_l2cap[] = {0x02, 0x00, 0x01, 0x00, 0x08, 0x35, 0x03, 0x19, 0x01,
                             0x00, 0x00, 0x05, 0x00};
  n = SdpHandle(search_l2cap, sizeof(search_l2cap), out, sizeof(out));
  assert(n == 22 && out[6] == 3 && out[20] == 3);
  // AVRCP: the remote control service class finds the target record.
  const u8 avrcp[] = {0x19, 0x11, 0x0E};
  n = SearchAttribute(avrcp, sizeof(avrcp), 0xFFFF, zero, 1, out, sizeof(out));
  const u8 avctp[] = {0x19, 0x01, 0x00, 0x09, 0x00, 0x17};
  const u8 target[] = {0x19, 0x11, 0x0C};
  assert(n > 20 && Contains(out, n, avctp, sizeof(avctp)) &&
         Contains(out, n, target, sizeof(target)) && !Contains(out, n, psm, sizeof(psm)));
  const u8 attr[] = {0x04, 0x00, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40,
                     0x35, 0x03, 0x09, 0x00, 0x04, 0x00};
  n = SdpHandle(attr, sizeof(attr), out, sizeof(out));
  assert(n && out[0] == 0x05 && Contains(out, n, psm, sizeof(psm)));
  // Unknown handle and malformed PDU give error responses.
  u8 bad[sizeof(attr)];
  memcpy(bad, attr, sizeof(attr));
  bad[8] = 0x09;
  n = SdpHandle(bad, sizeof(bad), out, sizeof(out));
  assert(n == 7 && out[0] == 0x01 && out[6] == 0x02);
  const u8 junk[] = {0x06, 0x00, 0x03, 0x00, 0x09, 0x01};
  n = SdpHandle(junk, sizeof(junk), out, sizeof(out));
  assert(n == 7 && out[0] == 0x01 && out[6] == 0x04);

  printf("Bluetooth SDP tests passed\n");
  return 0;
}
