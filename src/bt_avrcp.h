// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal AVRCP target over AVCTP (AVRCP 1.6, AVCTP 1.4): answers the
// headphones' commands so they accept the console as a media source and send
// their volume keys as PASS THROUGH commands. Written from the Bluetooth
// specifications; no third-party stack code. Stateless.
#ifndef USB_AUDIO360_BT_AVRCP_H_
#define USB_AUDIO360_BT_AVRCP_H_

#include "bt_hci.h"

namespace bt {

// PASS THROUGH operation IDs (AV/C Panel Subunit) we act on.
enum AvrcpOperation {
  kAvrcpVolumeUp = 0x41,
  kAvrcpVolumeDown = 0x42,
  kAvrcpMute = 0x43,
  kAvrcpPlay = 0x44,
  kAvrcpStop = 0x45,
  kAvrcpPause = 0x46
};

// Builds the response to one AVCTP command frame (L2CAP payload). Returns
// its length (0 = send nothing). *pressed receives a PASS THROUGH operation
// on key press, else 0.
unsigned AvrcpHandle(const u8* frame, unsigned length, u8* out,
                     unsigned capacity, u8* pressed);

// Absolute volume (AVRCP 1.4+), console as controller: the command that
// registers for the headphones' EVENT_VOLUME_CHANGED. Returns its length.
unsigned AvrcpRegisterVolume(u8 label, u8* out, unsigned capacity);
// Parses a response frame. Returns 1 for a volume INTERIM, 2 for CHANGED
// (re-register then), 3 for a rejection, 0 otherwise; *volume is 0..127.
int AvrcpVolumeResponse(const u8* frame, unsigned length, u8* volume);

}  // namespace bt

#endif  // USB_AUDIO360_BT_AVRCP_H_
