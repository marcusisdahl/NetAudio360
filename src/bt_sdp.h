// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal SDP server (Core Vol 3 Part B): answers the headphones' service
// queries with one A2DP Source record. Written from the Bluetooth
// specifications; no third-party stack code. Stateless: the continuation
// state carries the byte offset into the full response.
#ifndef USB_AUDIO360_BT_SDP_H_
#define USB_AUDIO360_BT_SDP_H_

#include "bt_hci.h"

namespace bt {

const u32 kSdpA2dpSourceHandle = 0x00010001;

// Builds the response PDU for one request PDU. out_capacity is the most the
// channel can carry (the remote's L2CAP MTU). Returns the response length,
// or 0 if nothing should be sent.
unsigned SdpHandle(const u8* request, unsigned length, u8* out,
                   unsigned out_capacity);

}  // namespace bt

#endif  // USB_AUDIO360_BT_SDP_H_
