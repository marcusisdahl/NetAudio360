// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/bt_avrcp.h"

using namespace bt;

int main() {
  u8 out[64];
  u8 pressed = 0xEE;
  // PASS THROUGH volume up, pressed then released (label 3).
  const u8 up[] = {0x30, 0x11, 0x0E, 0x00, 0x48, 0x7C, 0x41, 0x00};
  unsigned n = AvrcpHandle(up, sizeof(up), out, sizeof(out), &pressed);
  assert(n == 8 && out[0] == 0x32 && out[3] == 0x09 && out[5] == 0x7C &&
         out[6] == 0x41 && pressed == kAvrcpVolumeUp);
  const u8 released[] = {0x40, 0x11, 0x0E, 0x00, 0x48, 0x7C, 0xC1, 0x00};
  n = AvrcpHandle(released, sizeof(released), out, sizeof(out), &pressed);
  assert(n == 8 && out[0] == 0x42 && out[6] == 0xC1 && pressed == 0);
  // UNIT INFO and SUBUNIT INFO.
  const u8 unit[] = {0x00, 0x11, 0x0E, 0x01, 0xFF, 0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  n = AvrcpHandle(unit, sizeof(unit), out, sizeof(out), &pressed);
  assert(n == 11 && out[3] == 0x0C && out[6] == 0x07 && out[7] == 0x48);
  const u8 subunit[] = {0x10, 0x11, 0x0E, 0x01, 0xFF, 0x31, 0x07, 0xFF, 0xFF, 0xFF, 0xFF};
  n = AvrcpHandle(subunit, sizeof(subunit), out, sizeof(out), &pressed);
  assert(n == 11 && out[3] == 0x0C && out[6] == 0x07 && out[7] == 0x48);
  // GetCapabilities (events) and RegisterNotification (playback status).
  const u8 caps[] = {0x20, 0x11, 0x0E, 0x01, 0x48, 0x00, 0x00, 0x19, 0x58,
                     0x10, 0x00, 0x00, 0x01, 0x03};
  n = AvrcpHandle(caps, sizeof(caps), out, sizeof(out), &pressed);
  assert(n == 17 && out[3] == 0x0C && out[9] == 0x10 && out[12] == 4 &&
         out[13] == 0x03 && out[14] == 2);
  const u8 reg[] = {0x50, 0x11, 0x0E, 0x03, 0x48, 0x00, 0x00, 0x19, 0x58,
                    0x31, 0x00, 0x00, 0x05, 0x01, 0, 0, 0, 0};
  n = AvrcpHandle(reg, sizeof(reg), out, sizeof(out), &pressed);
  assert(n == 15 && out[3] == 0x0F && out[13] == 0x01 && out[14] == 0x01);
  const u8 volume_event[] = {0x50, 0x11, 0x0E, 0x03, 0x48, 0x00, 0x00, 0x19, 0x58,
                             0x31, 0x00, 0x00, 0x05, 0x0D, 0, 0, 0, 0};
  n = AvrcpHandle(volume_event, sizeof(volume_event), out, sizeof(out), &pressed);
  assert(n == 14 && out[3] == 0x0A);
  // Unknown opcode: NOT IMPLEMENTED. Wrong PID: IPID response.
  const u8 other[] = {0x60, 0x11, 0x0E, 0x00, 0x48, 0x40, 0x01};
  n = AvrcpHandle(other, sizeof(other), out, sizeof(out), &pressed);
  assert(n == 7 && out[0] == 0x62 && out[3] == 0x08);
  const u8 pid[] = {0x70, 0x11, 0x0F, 0x00, 0x48, 0x7C, 0x41, 0x00};
  n = AvrcpHandle(pid, sizeof(pid), out, sizeof(out), &pressed);
  assert(n == 3 && out[0] == 0x73);
  // Responses and fragments are ignored.
  const u8 response[] = {0x72, 0x11, 0x0E, 0x09, 0x48, 0x7C, 0x41, 0x00};
  assert(!AvrcpHandle(response, sizeof(response), out, sizeof(out), &pressed));
  printf("Bluetooth AVRCP tests passed\n");
  return 0;
}
