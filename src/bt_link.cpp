// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_link.h"

#include <string.h>

namespace bt {

namespace {

u16 Le16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }

bool Expired(unsigned now, unsigned deadline) {
  return (int)(now - deadline) >= 0;
}

// ACL packet types DM1, DH1, DM3, DH3, DM5, DH5 (Core 7.1.5).
const u16 kAclPacketTypes = 0xCC18;
// IO capability NoInputNoOutput: headphones have no display, so pairing is
// "Just Works". Authentication requirement 0x02: dedicated bonding (the user
// asked to pair), MITM protection not required.
const u8 kIoCapability = 0x03;
const u8 kAuthRequirement = 0x02;
// Legacy PIN used by headphones without SSP.
const char kLegacyPin[] = "0000";

}  // namespace

const char* LinkStateName(unsigned state) {
  static const char* names[] = {
    "idle", "connecting", "authenticating", "encrypting", "connected",
    "disconnecting"
  };
  return state < sizeof(names) / sizeof(names[0]) ? names[state] : "unknown";
}

const char* LinkFailureName(unsigned failure) {
  static const char* names[] = {
    "none", "command-status", "timeout", "connect", "authentication",
    "encryption", "closed", "hardware-error", "transport"
  };
  return failure < sizeof(names) / sizeof(names[0]) ? names[failure] : "unknown";
}

Link::Link(LinkObserver* observer) : observer_(observer) { Reset(); }

void Link::Reset() {
  state_ = kLinkIdle;
  memset(address_, 0, sizeof(address_));
  handle_ = 0;
  have_handle_ = false;
  new_key_ = false;
  used_stored_key_ = false;
  credits_ = 1;
  pending_opcode_ = 0;
  sent_ = false;
  queued_ = 0;
  deadline_ = 0;
  deadline_armed_ = false;
  command_deadline_ = 0;
  failure_ = kLinkOk;
  failure_opcode_ = 0;
  failure_status_ = 0;
  unhandled_ = 0;
}

bool Link::Enqueue(u16 opcode, const u8* params, u8 length) {
  if (queued_ == sizeof(queue_) / sizeof(queue_[0]) ||
      length > sizeof(queue_[0].params)) return false;
  Command& c = queue_[queued_++];
  c.opcode = opcode;
  c.length = length;
  if (length) memcpy(c.params, params, length);
  return true;
}

void Link::SetState(unsigned state, unsigned now, unsigned timeout_ms) {
  state_ = state;
  if (timeout_ms) {
    deadline_ = now + timeout_ms;
    deadline_armed_ = true;
  } else {
    deadline_armed_ = false;
  }
  if (observer_) observer_->OnLinkState(state_, address_);
}

bool Link::Connect(const Device& device, unsigned now) {
  if (state_ != kLinkIdle) return false;
  unsigned keep_unhandled = unhandled_;
  Reset();
  unhandled_ = keep_unhandled;
  memcpy(address_, device.address, 6);
  u8 p[13];
  memcpy(p, device.address, 6);
  p[6] = (u8)(kAclPacketTypes & 0xFF);
  p[7] = (u8)(kAclPacketTypes >> 8);
  p[8] = device.page_scan_repetition_mode;
  p[9] = 0;  // Reserved.
  u16 offset = device.clock_offset ? (u16)(device.clock_offset | 0x8000) : 0;
  p[10] = (u8)(offset & 0xFF);
  p[11] = (u8)(offset >> 8);
  p[12] = 1;  // Allow role switch: headphones often want to be master.
  Enqueue(kOpCreateConnection, p, sizeof(p));
  SetState(kLinkConnecting, now, kConnectTimeoutMs);
  return true;
}

bool Link::Connect(const u8* address, unsigned now) {
  Device d;
  memset(&d, 0, sizeof(d));
  memcpy(d.address, address, 6);
  d.page_scan_repetition_mode = 1;  // R1: the common default.
  return Connect(d, now);
}

bool Link::Disconnect(unsigned now) {
  if (state_ == kLinkIdle || state_ == kLinkDisconnecting) return false;
  if (!have_handle_) {
    // Still paging: there is no handle to disconnect. Finish now; a late
    // Connection Complete is answered with Disconnect in OnEvent.
    Finish(kLinkFailClosed, 0, 0x16);
    return true;
  }
  queued_ = sent_ ? 1 : 0;  // Drop replies not yet sent.
  u8 p[3] = {(u8)(handle_ & 0xFF), (u8)(handle_ >> 8), 0x13};
  Enqueue(kOpDisconnect, p, sizeof(p));
  SetState(kLinkDisconnecting, now, kDisconnectTimeoutMs);
  return true;
}

unsigned Link::NextCommand(u8* out, unsigned capacity) {
  if (!queued_ || sent_ || pending_opcode_ || !credits_) return 0;
  const Command& c = queue_[0];
  return BuildCommand(c.opcode, c.params, c.length, out, capacity);
}

void Link::CommandSent(unsigned now) {
  if (!queued_ || sent_) return;
  sent_ = true;
  pending_opcode_ = queue_[0].opcode;
  if (credits_) --credits_;
  command_deadline_ = now + kCommandTimeoutMs;
}

void Link::Abort(u8 status) {
  Finish(kLinkFailTransport, pending_opcode_ ? pending_opcode_
                                             : (queued_ ? queue_[0].opcode : 0),
         status);
}

void Link::Finish(unsigned failure, u16 opcode, u8 status) {
  if (failure_ == kLinkOk) {
    failure_ = failure;
    failure_opcode_ = opcode;
    failure_status_ = status;
  }
  state_ = kLinkIdle;
  have_handle_ = false;
  queued_ = 0;
  sent_ = false;
  pending_opcode_ = 0;
  deadline_armed_ = false;
  if (observer_) {
    observer_->OnLinkState(state_, address_);
    if (failure_ != kLinkOk)
      observer_->OnLinkFailed(failure_, failure_opcode_, failure_status_,
                              address_);
  }
}

void Link::Fail(unsigned failure, u16 opcode, u8 status, unsigned now) {
  if (failure_ == kLinkOk) {
    failure_ = failure;
    failure_opcode_ = opcode;
    failure_status_ = status;
  }
  // With a link up, close it cleanly; the failure is reported once the
  // controller confirms the disconnect.
  if (have_handle_ && state_ != kLinkDisconnecting) {
    Disconnect(now);
    return;
  }
  Finish(failure, opcode, status);
}

bool Link::ForUs(const u8* address) const {
  return state_ != kLinkIdle && !memcmp(address, address_, 6);
}

bool Link::ForHandle(const u8* p) const {
  return have_handle_ && (Le16(p) & 0x0FFF) == handle_;
}

void Link::OnCommandComplete(const u8* p, unsigned n, unsigned now) {
  if (n < 3) return;
  credits_ = p[0];
  u16 opcode = Le16(p + 1);
  if (!opcode || opcode != pending_opcode_) {
    if (opcode) ++unhandled_;
    return;
  }
  pending_opcode_ = 0;
  sent_ = false;
  if (queued_) {
    for (unsigned i = 1; i < queued_; ++i) queue_[i - 1] = queue_[i];
    --queued_;
  }
  // Pairing replies answer with Command Complete (status, BD_ADDR). A
  // rejected reply leaves the controller to fail authentication, which is
  // reported by Authentication Complete.
  if (n >= 4 && p[3]) ++unhandled_;
  (void)now;
}

void Link::OnCommandStatus(const u8* p, unsigned n, unsigned now) {
  if (n < 4) return;
  u8 status = p[0];
  credits_ = p[1];
  u16 opcode = Le16(p + 2);
  if (!opcode || opcode != pending_opcode_) {
    if (opcode) ++unhandled_;
    return;
  }
  pending_opcode_ = 0;
  sent_ = false;
  if (queued_) {
    for (unsigned i = 1; i < queued_; ++i) queue_[i - 1] = queue_[i];
    --queued_;
  }
  if (!status) return;
  if (opcode == kOpDisconnect) {
    // Already gone (e.g. 0x02 unknown connection): nothing to wait for.
    Finish(kLinkFailClosed, opcode, status);
    return;
  }
  Fail(kLinkFailCommand, opcode, status, now);
}

void Link::OnEvent(const u8* event, unsigned length, unsigned now) {
  if (length < 2 || length != 2u + event[1]) return;
  const u8* p = event + 2;
  unsigned n = event[1];
  switch (event[0]) {
    case kEvCommandComplete: OnCommandComplete(p, n, now); break;
    case kEvCommandStatus: OnCommandStatus(p, n, now); break;

    case kEvConnectionComplete: {
      if (n < 11) break;
      u8 status = p[0];
      u16 handle = (u16)(Le16(p + 1) & 0x0FFF);
      if (state_ != kLinkConnecting || memcmp(p + 3, address_, 6)) {
        // A connection we no longer want (abandoned while paging).
        if (!status) {
          u8 d[3] = {(u8)(handle & 0xFF), (u8)(handle >> 8), 0x13};
          Enqueue(kOpDisconnect, d, sizeof(d));
        }
        break;
      }
      if (status) { Finish(kLinkFailConnect, kOpCreateConnection, status); break; }
      handle_ = handle;
      have_handle_ = true;
      u8 a[2] = {(u8)(handle_ & 0xFF), (u8)(handle_ >> 8)};
      Enqueue(kOpAuthenticationRequested, a, sizeof(a));
      SetState(kLinkAuthenticating, now, kConnectTimeoutMs);
      break;
    }

    case kEvLinkKeyRequest: {
      if (n < 6 || !ForUs(p)) { ++unhandled_; break; }
      u8 key[16];
      if (observer_ && observer_->FindLinkKey(p, key)) {
        u8 r[22];
        memcpy(r, p, 6);
        memcpy(r + 6, key, 16);
        used_stored_key_ = true;
        Enqueue(kOpLinkKeyRequestReply, r, sizeof(r));
      } else {
        Enqueue(kOpLinkKeyRequestNegativeReply, p, 6);
      }
      break;
    }

    case kEvIoCapabilityRequest: {
      if (n < 6 || !ForUs(p)) { ++unhandled_; break; }
      u8 r[9];
      memcpy(r, p, 6);
      r[6] = kIoCapability;
      r[7] = 0;  // No OOB data.
      r[8] = kAuthRequirement;
      Enqueue(kOpIoCapabilityRequestReply, r, sizeof(r));
      break;
    }

    case kEvUserConfirmationRequest:
      // Just Works: both sides lack a display, so confirm automatically.
      if (n < 6 || !ForUs(p)) { ++unhandled_; break; }
      Enqueue(kOpUserConfirmationRequestReply, p, 6);
      break;

    case kEvUserPasskeyRequest:
      // We cannot show or enter a passkey.
      if (n < 6 || !ForUs(p)) { ++unhandled_; break; }
      Enqueue(kOpUserPasskeyRequestNegativeReply, p, 6);
      break;

    case kEvPinCodeRequest: {
      if (n < 6 || !ForUs(p)) { ++unhandled_; break; }
      u8 r[23];
      memset(r, 0, sizeof(r));
      memcpy(r, p, 6);
      r[6] = (u8)(sizeof(kLegacyPin) - 1);
      memcpy(r + 7, kLegacyPin, sizeof(kLegacyPin) - 1);
      Enqueue(kOpPinCodeRequestReply, r, sizeof(r));
      break;
    }

    case kEvLinkKeyNotification:
      if (n < 23 || !ForUs(p)) { ++unhandled_; break; }
      new_key_ = true;
      if (observer_) observer_->OnLinkKey(p, p + 6, p[22]);
      break;

    case kEvIoCapabilityResponse:
    case kEvSimplePairingComplete:
      // Outcome is reported by Authentication Complete.
      break;

    case kEvAuthenticationComplete: {
      if (n < 3 || !ForHandle(p + 1) || state_ != kLinkAuthenticating) {
        ++unhandled_;
        break;
      }
      u8 status = p[0];
      if (status) {
        // 0x06 PIN or key missing / 0x05 failure with our stored key: the
        // headphones were reset or paired elsewhere.
        if (used_stored_key_ && !new_key_ && (status == 0x05 || status == 0x06) &&
            observer_)
          observer_->OnLinkKeyRejected(address_);
        Fail(kLinkFailAuth, kOpAuthenticationRequested, status, now);
        break;
      }
      u8 e[3] = {(u8)(handle_ & 0xFF), (u8)(handle_ >> 8), 1};
      Enqueue(kOpSetConnectionEncryption, e, sizeof(e));
      SetState(kLinkEncrypting, now, kCommandTimeoutMs * 2);
      break;
    }

    case kEvEncryptionChange: {
      if (n < 4 || !ForHandle(p + 1)) { ++unhandled_; break; }
      if (state_ != kLinkEncrypting) break;  // E.g. a later key refresh.
      if (p[0] || !p[3]) {
        Fail(kLinkFailEncrypt, kOpSetConnectionEncryption, p[0], now);
        break;
      }
      SetState(kLinkConnected, now, 0);
      break;
    }

    case kEvDisconnectionComplete: {
      if (n < 4 || !ForHandle(p + 1)) { ++unhandled_; break; }
      bool requested = state_ == kLinkDisconnecting;
      // A disconnect we asked for with no earlier failure is a clean close.
      Finish(requested && failure_ == kLinkOk ? kLinkOk : kLinkFailClosed,
             0, p[3]);
      break;
    }

    case kEvConnectionRequest:
      // Incoming connections are not accepted yet (page scan stays off).
      ++unhandled_;
      break;

    case kEvHardwareError:
      if (state_ != kLinkIdle) Finish(kLinkFailHardware, 0, n ? p[0] : 0);
      break;

    default:
      ++unhandled_;
      break;
  }
}

void Link::Tick(unsigned now) {
  if (state_ == kLinkIdle) return;
  if (sent_ && Expired(now, command_deadline_)) {
    u16 opcode = pending_opcode_;
    sent_ = false;
    pending_opcode_ = 0;
    credits_ = 1;
    if (state_ == kLinkDisconnecting) {
      Finish(kLinkFailTimeout, opcode, 0);
    } else {
      Fail(kLinkFailTimeout, opcode, 0, now);
    }
    return;
  }
  if (deadline_armed_ && Expired(now, deadline_)) {
    if (state_ == kLinkDisconnecting) Finish(kLinkFailTimeout, kOpDisconnect, 0);
    else Fail(kLinkFailTimeout, 0, 0, now);
  }
}

// ---------------------------------------------------------------------------

namespace {

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool HexByte(const char* p, u8* out) {
  int hi = HexValue(p[0]), lo = HexValue(p[1]);
  if (hi < 0 || lo < 0) return false;
  *out = (u8)(hi * 16 + lo);
  return true;
}

void CopyText(const char* source, unsigned length, char* out) {
  if (length >= kMaxNameBytes) length = kMaxNameBytes - 1;
  CopyName((const u8*)source, length, out, kMaxNameBytes);
  for (char* c = out; *c; ++c)
    if ((unsigned char)*c < 32 || *c == 127) *c = ' ';
}

}  // namespace

const PairedDevice* PairedStore::Find(const u8* address) const {
  for (unsigned i = 0; i < count_; ++i)
    if (!memcmp(devices_[i].address, address, 6)) return &devices_[i];
  return 0;
}

void PairedStore::Put(const u8* address, const u8* key, u8 key_type,
                      const char* name) {
  PairedDevice d;
  memset(&d, 0, sizeof(d));
  memcpy(d.address, address, 6);
  memcpy(d.key, key, 16);
  d.key_type = key_type;
  const PairedDevice* old = Find(address);
  if (name && name[0]) CopyText(name, (unsigned)strlen(name), d.name);
  else if (old) memcpy(d.name, old->name, sizeof(d.name));
  Remove(address);
  if (count_ == kMaxPaired) --count_;
  for (unsigned i = count_; i > 0; --i) devices_[i] = devices_[i - 1];
  devices_[0] = d;
  ++count_;
}

bool PairedStore::Remove(const u8* address) {
  for (unsigned i = 0; i < count_; ++i) {
    if (memcmp(devices_[i].address, address, 6)) continue;
    for (unsigned j = i + 1; j < count_; ++j) devices_[j - 1] = devices_[j];
    --count_;
    return true;
  }
  return false;
}

unsigned PairedStore::Format(char* out, unsigned capacity) const {
  static const char header[] = "# usb_audio360 Bluetooth pairings\r\n";
  static const char hex[] = "0123456789abcdef";
  unsigned n = 0;
  unsigned need = sizeof(header);
  for (unsigned i = 0; i < count_; ++i)
    need += 18 + 33 + 4 + (unsigned)strlen(devices_[i].name) + 2;
  if (!out || capacity < need) return 0;
  memcpy(out, header, sizeof(header) - 1);
  n = sizeof(header) - 1;
  for (unsigned i = 0; i < count_; ++i) {
    const PairedDevice& d = devices_[i];
    FormatAddress(d.address, out + n);
    n += 17;
    out[n++] = ' ';
    for (int k = 0; k < 16; ++k) {
      out[n++] = hex[d.key[k] >> 4];
      out[n++] = hex[d.key[k] & 15];
    }
    out[n++] = ' ';
    if (d.key_type >= 10) out[n++] = (char)('0' + d.key_type / 10);
    out[n++] = (char)('0' + d.key_type % 10);
    out[n++] = ' ';
    unsigned name_length = (unsigned)strlen(d.name);
    memcpy(out + n, d.name, name_length);
    n += name_length;
    out[n++] = '\r';
    out[n++] = '\n';
  }
  out[n] = 0;
  return n;
}

bool PairedStore::Parse(const char* text, unsigned length) {
  PairedDevice parsed[kMaxPaired];
  unsigned count = 0;
  unsigned at = 0;
  while (at < length) {
    unsigned end = at;
    while (end < length && text[end] != '\n') ++end;
    unsigned line_end = end;
    if (line_end > at && text[line_end - 1] == '\r') --line_end;
    const char* line = text + at;
    unsigned n = line_end - at;
    at = end + 1;
    if (!n || line[0] == '#') continue;
    // Address (17) + space + key (32) + space + type (1-3 digits).
    if (n < 17 + 1 + 32 + 1 + 1 || count == kMaxPaired) return false;
    PairedDevice d;
    memset(&d, 0, sizeof(d));
    for (int i = 0; i < 6; ++i) {
      if (!HexByte(line + i * 3, &d.address[5 - i])) return false;
      if (i < 5 && line[i * 3 + 2] != ':') return false;
    }
    if (line[17] != ' ') return false;
    for (int k = 0; k < 16; ++k)
      if (!HexByte(line + 18 + k * 2, &d.key[k])) return false;
    if (line[50] != ' ') return false;
    unsigned p = 51, type = 0, digits = 0;
    while (p < n && line[p] >= '0' && line[p] <= '9' && digits < 3) {
      type = type * 10 + (unsigned)(line[p++] - '0');
      ++digits;
    }
    if (!digits || type > 255 || (p < n && line[p] != ' ')) return false;
    d.key_type = (u8)type;
    if (p < n) CopyText(line + p + 1, n - p - 1, d.name);
    parsed[count++] = d;
  }
  for (unsigned i = 0; i < count; ++i) devices_[i] = parsed[i];
  count_ = count;
  return true;
}

}  // namespace bt
