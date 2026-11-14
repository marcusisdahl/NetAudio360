// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_avrcp.h"

#include <string.h>

namespace bt {

namespace {

enum {
  kNotImplemented = 0x08, kAccepted = 0x09, kRejected = 0x0A,
  kStable = 0x0C, kInterim = 0x0F
};
enum { kUnitInfo = 0x30, kSubunitInfo = 0x31, kPassThrough = 0x7C,
       kVendorDependent = 0x00 };
enum { kGetCapabilities = 0x10, kGetPlayStatus = 0x30,
       kRegisterNotification = 0x31 };
const u8 kBtSig[3] = {0x00, 0x19, 0x58};
const u8 kPanel = 0x48;  // Subunit type 9 (panel), ID 0.

unsigned Header(const u8* in, u8* out, u8 response) {
  out[0] = (u8)((in[0] & 0xF0) | 0x02);  // Same label, single, response.
  out[1] = in[1];
  out[2] = in[2];
  out[3] = response;
  out[4] = in[4];
  out[5] = in[5];
  return 6;
}

// Vendor-dependent response: company, PDU, packet type, length, params.
unsigned Vendor(const u8* in, u8* out, unsigned capacity, u8 response, u8 pdu,
                const u8* params, unsigned n) {
  if (capacity < 6 + 7 + n) return 0;
  unsigned at = Header(in, out, response);
  out[4] = kPanel;
  memcpy(out + at, kBtSig, 3);
  at += 3;
  out[at++] = pdu;
  out[at++] = 0;  // Single packet.
  out[at++] = (u8)(n >> 8);
  out[at++] = (u8)n;
  if (n) memcpy(out + at, params, n);
  return at + n;
}

}  // namespace

unsigned AvrcpHandle(const u8* in, unsigned n, u8* out, unsigned capacity,
                     u8* pressed) {
  *pressed = 0;
  if (n < 3 || capacity < 16) return 0;
  if ((in[0] & 0x0C) != 0) return 0;  // Fragmented: not used by AVRCP here.
  if (in[0] & 0x02) return 0;         // A response; we send no commands.
  if (in[1] != 0x11 || in[2] != 0x0E) {
    // Not the A/V remote control profile: invalid PID response.
    out[0] = (u8)((in[0] & 0xF0) | 0x03);
    out[1] = in[1];
    out[2] = in[2];
    return 3;
  }
  if (n < 6) return 0;
  const u8 opcode = in[5];
  const u8* operands = in + 6;
  const unsigned operand_length = n - 6;

  if (opcode == kUnitInfo || opcode == kSubunitInfo) {
    unsigned at = Header(in, out, kStable);
    // UNIT INFO: 0x07, panel unit, company ID. SUBUNIT INFO: page 0, then
    // the panel subunit and three unused slots.
    out[at++] = 0x07;
    out[at++] = kPanel;
    out[at++] = 0xFF;
    out[at++] = 0xFF;
    out[at++] = 0xFF;
    if (opcode == kSubunitInfo)
      out[6] = (u8)((operand_length ? operands[0] & 0x70 : 0) | 0x07);
    return at;
  }
  if (opcode == kPassThrough) {
    if (operand_length < 2 || 6 + operand_length > capacity) return 0;
    unsigned at = Header(in, out, kAccepted);
    memcpy(out + at, operands, operand_length);
    if (!(operands[0] & 0x80)) *pressed = (u8)(operands[0] & 0x7F);
    return at + operand_length;
  }
  if (opcode == kVendorDependent && operand_length >= 7 &&
      !memcmp(operands, kBtSig, 3)) {
    const u8 pdu = operands[3];
    const unsigned length = (operands[5] << 8) | operands[6];
    const u8* p = operands + 7;
    if (7 + length > operand_length) {
      u8 e = 0x01;  // Invalid parameter.
      return Vendor(in, out, capacity, kRejected, pdu, &e, 1);
    }
    if (pdu == kGetCapabilities && length >= 1) {
      if (p[0] == 0x02) {  // Company IDs: Bluetooth SIG.
        u8 r[5] = {0x02, 1, kBtSig[0], kBtSig[1], kBtSig[2]};
        return Vendor(in, out, capacity, kStable, pdu, r, sizeof(r));
      }
      if (p[0] == 0x03) {  // Events: playback status, track changed.
        u8 r[4] = {0x03, 2, 0x01, 0x02};
        return Vendor(in, out, capacity, kStable, pdu, r, sizeof(r));
      }
      u8 e = 0x01;
      return Vendor(in, out, capacity, kRejected, pdu, &e, 1);
    }
    if (pdu == kGetPlayStatus) {
      u8 r[9] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
      return Vendor(in, out, capacity, kStable, pdu, r, sizeof(r));
    }
    if (pdu == kRegisterNotification && length >= 1) {
      if (p[0] == 0x01) {  // Playback status: playing.
        u8 r[2] = {0x01, 0x01};
        return Vendor(in, out, capacity, kInterim, pdu, r, sizeof(r));
      }
      if (p[0] == 0x02) {  // Track changed: no track selected.
        u8 r[9] = {0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        return Vendor(in, out, capacity, kInterim, pdu, r, sizeof(r));
      }
      u8 e = 0x01;
      return Vendor(in, out, capacity, kRejected, pdu, &e, 1);
    }
    u8 e = 0x00;  // Invalid command.
    return Vendor(in, out, capacity, kRejected, pdu, &e, 1);
  }
  // Anything else: NOT IMPLEMENTED, echoing the frame.
  if (n > capacity) return 0;
  memcpy(out, in, n);
  Header(in, out, kNotImplemented);
  return n;
}

}  // namespace bt
