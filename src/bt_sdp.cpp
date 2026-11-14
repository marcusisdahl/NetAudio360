// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_sdp.h"

#include <string.h>

namespace bt {

namespace {

enum {
  kErrorResponse = 0x01,
  kSearchRequest = 0x02, kSearchResponse = 0x03,
  kAttributeRequest = 0x04, kAttributeResponse = 0x05,
  kSearchAttributeRequest = 0x06, kSearchAttributeResponse = 0x07
};
enum {
  kErrBadSyntax = 0x0003, kErrBadHandle = 0x0002, kErrBadPduSize = 0x0004,
  kErrBadContinuation = 0x0005
};

u16 Be16(const u8* p) { return (u16)((p[0] << 8) | p[1]); }
u32 Be32(const u8* p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
void PutBe16(u8* p, unsigned v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }

// One attribute: its ID and its encoded value (a data element).
struct Attribute {
  u16 id;
  const u8* value;
  unsigned length;
};

// A2DP Source record (A2DP 1.3 section 5.3, Core Vol 3 Part B 5.1).
const u8 kHandle[] = {0x0A, 0x00, 0x01, 0x00, 0x01};
const u8 kClasses[] = {0x35, 0x03, 0x19, 0x11, 0x0A};          // AudioSource
const u8 kProtocols[] = {0x35, 0x10,
                         0x35, 0x06, 0x19, 0x01, 0x00,           // L2CAP
                         0x09, 0x00, 0x19,                       //  PSM AVDTP
                         0x35, 0x06, 0x19, 0x00, 0x19,           // AVDTP
                         0x09, 0x01, 0x03};                      //  1.3
const u8 kBrowse[] = {0x35, 0x03, 0x19, 0x10, 0x02};            // PublicBrowseRoot
const u8 kLanguages[] = {0x35, 0x09, 0x09, 0x65, 0x6E,          // "en"
                         0x09, 0x00, 0x6A, 0x09, 0x01, 0x00};    // UTF-8, base 0x100
const u8 kProfiles[] = {0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0D,  // A2DP
                        0x09, 0x01, 0x03};                           // 1.3
const u8 kName[] = {0x25, 0x0C, 'A', 'u', 'd', 'i', 'o', ' ',
                    'S', 'o', 'u', 'r', 'c', 'e'};
const u8 kFeatures[] = {0x09, 0x00, 0x01};                       // Player

const Attribute kRecord[] = {
  {0x0000, kHandle, sizeof(kHandle)},
  {0x0001, kClasses, sizeof(kClasses)},
  {0x0004, kProtocols, sizeof(kProtocols)},
  {0x0005, kBrowse, sizeof(kBrowse)},
  {0x0006, kLanguages, sizeof(kLanguages)},
  {0x0009, kProfiles, sizeof(kProfiles)},
  {0x0100, kName, sizeof(kName)},
  {0x0311, kFeatures, sizeof(kFeatures)},
};
const unsigned kRecordCount = sizeof(kRecord) / sizeof(kRecord[0]);

// UUIDs the record contains (as 32-bit short forms of the base UUID).
const u32 kRecordUuids[] = {0x110A, 0x0100, 0x0019, 0x1002, 0x110D};

// Reads a data element header. Returns the header size, or 0 if malformed.
unsigned Element(const u8* p, unsigned n, u8* type, unsigned* length) {
  if (!n) return 0;
  *type = (u8)(p[0] >> 3);
  u8 size = (u8)(p[0] & 7);
  if (size < 5) {
    static const unsigned kSizes[] = {1, 2, 4, 8, 16};
    *length = *type == 0 ? 0 : kSizes[size];
    return 1;
  }
  if (size == 5) { if (n < 2) return 0; *length = p[1]; return 2; }
  if (size == 6) { if (n < 3) return 0; *length = Be16(p + 1); return 3; }
  if (n < 5) return 0;
  *length = Be32(p + 1);
  return 5;
}

// Reads a data element sequence; *body/*body_length is its content and the
// return value the total bytes used, 0 if malformed.
unsigned Sequence(const u8* p, unsigned n, const u8** body, unsigned* body_length) {
  u8 type = 0;
  unsigned length = 0;
  unsigned header = Element(p, n, &type, &length);
  if (!header || type != 6 || header + length > n) return 0;
  *body = p + header;
  *body_length = length;
  return header + length;
}

const u8 kBaseUuid[12] = {0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
                          0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};

// True when every UUID in the search pattern is in our record.
bool PatternMatches(const u8* p, unsigned n, bool* ok) {
  *ok = false;
  unsigned count = 0;
  bool all = true;
  while (n) {
    u8 type = 0;
    unsigned length = 0;
    unsigned header = Element(p, n, &type, &length);
    if (!header || type != 3 || header + length > n) return false;
    u32 uuid = 0;
    bool known = true;
    if (length == 2) uuid = Be16(p + header);
    else if (length == 4) uuid = Be32(p + header);
    else if (length == 16 && !memcmp(p + header + 4, kBaseUuid, 12))
      uuid = Be32(p + header);
    else if (length == 16) known = false;
    else return false;
    bool found = false;
    for (unsigned i = 0; known && i < sizeof(kRecordUuids) / sizeof(kRecordUuids[0]); ++i)
      if (kRecordUuids[i] == uuid) found = true;
    if (!found) all = false;
    ++count;
    p += header + length;
    n -= header + length;
  }
  if (!count || count > 12) return false;
  *ok = true;
  return all;
}

// Writes the attributes selected by an attribute ID list as one data
// element sequence. Returns its length, 0 if the list is malformed.
unsigned WriteAttributes(const u8* ids, unsigned n, u8* out, unsigned capacity) {
  bool selected[kRecordCount];
  for (unsigned i = 0; i < kRecordCount; ++i) selected[i] = false;
  bool any = false;
  while (n) {
    u8 type = 0;
    unsigned length = 0;
    unsigned header = Element(ids, n, &type, &length);
    if (!header || type != 1 || header + length > n) return 0;
    u32 low, high;
    if (length == 2) { low = high = Be16(ids + header); }
    else if (length == 4) { low = Be16(ids + header); high = Be16(ids + header + 2); }
    else return 0;
    for (unsigned i = 0; i < kRecordCount; ++i)
      if (kRecord[i].id >= low && kRecord[i].id <= high) selected[i] = true;
    any = true;
    ids += header + length;
    n -= header + length;
  }
  if (!any) return 0;
  unsigned body = 0;
  for (unsigned i = 0; i < kRecordCount; ++i)
    if (selected[i]) body += 3 + kRecord[i].length;
  if (3 + body > capacity) return 0;
  out[0] = 0x36;  // Sequence, 16-bit length (always fits our record).
  PutBe16(out + 1, body);
  unsigned at = 3;
  for (unsigned i = 0; i < kRecordCount; ++i) {
    if (!selected[i]) continue;
    out[at] = 0x09;
    PutBe16(out + at + 1, kRecord[i].id);
    memcpy(out + at + 3, kRecord[i].value, kRecord[i].length);
    at += 3 + kRecord[i].length;
  }
  return at;
}

unsigned Error(u16 transaction, u16 code, u8* out, unsigned capacity) {
  if (capacity < 7) return 0;
  out[0] = kErrorResponse;
  PutBe16(out + 1, transaction);
  PutBe16(out + 3, 2);
  PutBe16(out + 5, code);
  return 7;
}

// Continuation state we hand out: 2 bytes = offset into the full list.
bool ReadContinuation(const u8* p, unsigned n, unsigned* offset) {
  if (n < 1) return false;
  if (p[0] == 0) { *offset = 0; return n == 1; }
  if (p[0] != 2 || n != 3) return false;
  *offset = Be16(p + 1);
  return true;
}

// Attribute (list) response with continuation: header, byte count, chunk,
// continuation state.
unsigned Chunked(u8 pdu, u16 transaction, const u8* full, unsigned full_length,
                 unsigned offset, unsigned max_bytes, u8* out, unsigned capacity) {
  if (offset > full_length) return Error(transaction, kErrBadContinuation, out, capacity);
  if (capacity < 5 + 2 + 3 + 1) return 0;
  unsigned room = capacity - (5 + 2 + 3);
  unsigned chunk = full_length - offset;
  if (chunk > max_bytes) chunk = max_bytes;
  if (chunk > room) chunk = room;
  bool more = offset + chunk < full_length;
  out[0] = pdu;
  PutBe16(out + 1, transaction);
  PutBe16(out + 5, chunk);
  memcpy(out + 7, full + offset, chunk);
  unsigned at = 7 + chunk;
  if (more) {
    out[at++] = 2;
    PutBe16(out + at, offset + chunk);
    at += 2;
  } else {
    out[at++] = 0;
  }
  PutBe16(out + 3, at - 5);
  return at;
}

}  // namespace

unsigned SdpHandle(const u8* request, unsigned length, u8* out,
                   unsigned capacity) {
  if (length < 5 || !out) return 0;
  u8 pdu = request[0];
  u16 transaction = Be16(request + 1);
  unsigned parameters = Be16(request + 3);
  if (5 + parameters != length)
    return Error(transaction, kErrBadPduSize, out, capacity);
  const u8* p = request + 5;
  unsigned n = parameters;
  u8 full[256];

  if (pdu == kSearchRequest) {
    const u8* pattern; unsigned pattern_length;
    unsigned used = Sequence(p, n, &pattern, &pattern_length);
    if (!used || used + 2 > n) return Error(transaction, kErrBadSyntax, out, capacity);
    bool valid = false;
    bool match = PatternMatches(pattern, pattern_length, &valid);
    unsigned max_records = Be16(p + used);
    unsigned offset = 0;
    if (!valid || !ReadContinuation(p + used + 2, n - used - 2, &offset))
      return Error(transaction, kErrBadSyntax, out, capacity);
    unsigned count = match && max_records ? 1 : 0;
    if (capacity < 5 + 4 + 4 * count + 1) return 0;
    out[0] = kSearchResponse;
    PutBe16(out + 1, transaction);
    PutBe16(out + 5, count);
    PutBe16(out + 7, count);
    unsigned at = 9;
    if (count) {
      out[at] = 0x00; out[at + 1] = 0x01; out[at + 2] = 0x00; out[at + 3] = 0x01;
      at += 4;
    }
    out[at++] = 0;
    PutBe16(out + 3, at - 5);
    return at;
  }

  if (pdu == kAttributeRequest) {
    if (n < 6) return Error(transaction, kErrBadSyntax, out, capacity);
    u32 handle = Be32(p);
    unsigned max_bytes = Be16(p + 4);
    const u8* ids; unsigned ids_length;
    unsigned used = Sequence(p + 6, n - 6, &ids, &ids_length);
    unsigned offset = 0;
    if (!used || max_bytes < 7 ||
        !ReadContinuation(p + 6 + used, n - 6 - used, &offset))
      return Error(transaction, kErrBadSyntax, out, capacity);
    if (handle != kSdpA2dpSourceHandle)
      return Error(transaction, kErrBadHandle, out, capacity);
    unsigned full_length = WriteAttributes(ids, ids_length, full, sizeof(full));
    if (!full_length) return Error(transaction, kErrBadSyntax, out, capacity);
    return Chunked(kAttributeResponse, transaction, full, full_length, offset,
                   max_bytes, out, capacity);
  }

  if (pdu == kSearchAttributeRequest) {
    const u8* pattern; unsigned pattern_length;
    unsigned used = Sequence(p, n, &pattern, &pattern_length);
    if (!used || used + 2 > n) return Error(transaction, kErrBadSyntax, out, capacity);
    bool valid = false;
    bool match = PatternMatches(pattern, pattern_length, &valid);
    unsigned max_bytes = Be16(p + used);
    const u8* ids; unsigned ids_length;
    unsigned used2 = Sequence(p + used + 2, n - used - 2, &ids, &ids_length);
    unsigned offset = 0;
    if (!valid || !used2 || max_bytes < 7 ||
        !ReadContinuation(p + used + 2 + used2, n - used - 2 - used2, &offset))
      return Error(transaction, kErrBadSyntax, out, capacity);
    // A sequence of attribute lists: ours if the pattern matched, else empty.
    unsigned full_length = 3;
    if (match) {
      unsigned list = WriteAttributes(ids, ids_length, full + 3, sizeof(full) - 3);
      if (!list) return Error(transaction, kErrBadSyntax, out, capacity);
      full_length += list;
    }
    full[0] = 0x36;
    PutBe16(full + 1, full_length - 3);
    return Chunked(kSearchAttributeResponse, transaction, full, full_length,
                   offset, max_bytes, out, capacity);
  }

  return Error(transaction, kErrBadSyntax, out, capacity);
}

}  // namespace bt
