// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_hci.h"

#include <string.h>

namespace bt {

namespace {

u16 Le16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
u32 Le24(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16); }

// Default event mask (Core Vol 4 Part E 7.3.1) plus Extended Inquiry Result
// (bit 46), Encryption Key Refresh Complete (47), the Secure Simple Pairing
// events (48-53: IO Capability Request/Response, User Confirmation/Passkey
// Request, Remote OOB Data Request, Simple Pairing Complete), Link
// Supervision Timeout Changed (55), User Passkey Notification (58), Keypress
// Notification (59) and Remote Host Supported Features Notification (60).
const u8 kEventMask[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDF, 0xBF, 0x1C};
// General/Unlimited Inquiry Access Code 0x9E8B33, little-endian.
const u8 kGiac[3] = {0x33, 0x8B, 0x9E};
const unsigned kInquiryUnitMs = 1280;
const unsigned kInquirySlackMs = 5000;

bool Expired(unsigned now, unsigned deadline) {
  return (int)(now - deadline) >= 0;
}

}  // namespace

// ---------------------------------------------------------------------------

bool FindHciEndpoints(const u8* c, size_t length, HciEndpoints* out) {
  if (!c || !out || length < 9 || c[1] != 2) return false;
  size_t total = Le16(c + 2);
  if (total < length) length = total;
  bool candidate = false;
  unsigned declared = 0, found = 0;
  HciEndpoints e;
  memset(&e, 0, sizeof(e));
  size_t offset = 0;
  for (;;) {
    bool at_end = offset + 2 > length;
    bool next_interface = !at_end && c[offset + 1] == 4;
    if ((at_end || next_interface) && candidate) {
      if (declared == 3 && found == 3 && e.event_address &&
          e.acl_in_address && e.acl_out_address) {
        *out = e;
        return true;
      }
      candidate = false;
    }
    if (at_end) return false;
    u8 bl = c[offset];
    if (bl < 2 || offset + bl > length) return false;
    const u8* d = c + offset;
    if (d[1] == 4 && bl >= 9) {
      candidate = d[3] == 0 && d[5] == 0xE0 && d[6] == 0x01 && d[7] == 0x01;
      memset(&e, 0, sizeof(e));
      e.interface_number = d[2];
      declared = d[4];
      found = 0;
    } else if (d[1] == 5 && bl >= 7 && candidate) {
      u8 address = d[2];
      u8 type = d[3] & 3;
      u16 mps = (u16)(Le16(d + 4) & 0x7FF);
      ++found;
      if (type == 3 && (address & 0x80) && !e.event_address) {
        e.event_address = address;
        e.event_max_packet = mps;
        e.event_interval = d[6];
      } else if (type == 2 && (address & 0x80) && !e.acl_in_address) {
        e.acl_in_address = address;
        e.acl_in_max_packet = mps;
      } else if (type == 2 && !(address & 0x80) && !e.acl_out_address) {
        e.acl_out_address = address;
        e.acl_out_max_packet = mps;
      } else {
        candidate = false;  // Unexpected endpoint: not the primary interface.
      }
      if (candidate && (mps == 0)) candidate = false;
    }
    offset += bl;
  }
}

// ---------------------------------------------------------------------------

unsigned BuildCommand(u16 opcode, const u8* params, u8 param_length,
                      u8* out, unsigned capacity) {
  unsigned total = 3u + param_length;
  if (!out || capacity < total || (param_length && !params)) return 0;
  out[0] = (u8)(opcode & 0xFF);
  out[1] = (u8)(opcode >> 8);
  out[2] = param_length;
  if (param_length) memcpy(out + 3, params, param_length);
  return total;
}

size_t EventAssembler::Push(const u8* data, size_t length, bool* complete) {
  *complete = false;
  if (done_) { have_ = 0; done_ = false; }
  size_t used = 0;
  while (used < length) {
    unsigned need = have_ < 2 ? 2 : 2u + buffer_[1];
    size_t take = need - have_;
    if (take > length - used) take = length - used;
    memcpy(buffer_ + have_, data + used, take);
    have_ += (unsigned)take;
    used += take;
    if (have_ >= 2 && have_ == 2u + buffer_[1]) {
      done_ = true;
      *complete = true;
      return used;
    }
  }
  return used;
}

void CopyName(const u8* source, size_t source_length, char* name,
              size_t capacity) {
  if (!name || !capacity) return;
  size_t n = 0;
  while (source && n < source_length && n + 1 < capacity && source[n]) {
    name[n] = (char)source[n];
    ++n;
  }
  // Drop a trailing incomplete UTF-8 sequence left by truncation.
  if (n) {
    size_t lead = n - 1;
    while (lead > 0 && ((u8)name[lead] & 0xC0) == 0x80) --lead;
    u8 b = (u8)name[lead];
    size_t expected = b < 0x80 ? 1 : (b & 0xE0) == 0xC0 ? 2 :
                      (b & 0xF0) == 0xE0 ? 3 : (b & 0xF8) == 0xF0 ? 4 : 1;
    if (lead + expected > n) n = lead;
  }
  name[n] = 0;
}

bool EirName(const u8* eir, size_t length, char* name, size_t capacity) {
  const u8* shortened = 0;
  size_t shortened_length = 0;
  size_t i = 0;
  while (eir && i < length) {
    u8 field = eir[i];
    if (!field || i + 1 + field > length) break;
    u8 type = eir[i + 1];
    if (type == 0x09) {
      CopyName(eir + i + 2, field - 1u, name, capacity);
      return true;
    }
    if (type == 0x08 && !shortened) {
      shortened = eir + i + 2;
      shortened_length = field - 1u;
    }
    i += 1u + field;
  }
  if (!shortened) return false;
  CopyName(shortened, shortened_length, name, capacity);
  return true;
}

void FormatAddress(const u8* a, char* out) {
  static const char hex[] = "0123456789ABCDEF";
  for (int i = 0; i < 6; ++i) {
    u8 b = a[5 - i];
    out[i * 3] = hex[b >> 4];
    out[i * 3 + 1] = hex[b & 15];
    out[i * 3 + 2] = i == 5 ? 0 : ':';
  }
}

const char* StageName(unsigned stage) {
  static const char* names[] = {
    "idle", "reset", "read-version", "read-address", "buffer-size",
    "event-mask",
    "inquiry-mode", "simple-pairing", "local-name", "inquiry", "names",
    "done", "failed"
  };
  return stage < sizeof(names) / sizeof(names[0]) ? names[stage] : "unknown";
}

const char* FailureName(unsigned failure) {
  static const char* names[] = {
    "none", "command-status", "command-timeout", "inquiry-timeout",
    "malformed-event", "hardware-error", "transport"
  };
  return failure < sizeof(names) / sizeof(names[0]) ? names[failure] : "unknown";
}

// ---------------------------------------------------------------------------

Scanner::Scanner(ScanObserver* observer) : observer_(observer) {
  stage_ = kStageIdle;
  credits_ = 0;
  pending_opcode_ = 0;
  built_opcode_ = 0;
  command_ready_ = false;
  inquiry_mode_ = 2;
  inquire_on_start_ = true;
  inquiries_ = 0;
  deadline_ = 0;
  deadline_armed_ = false;
  name_index_ = -1;
  name_wait_ = false;
  memset(local_address_, 0, sizeof(local_address_));
  acl_mtu_ = 27;      // Smallest an ACL-U controller may report.
  acl_buffers_ = 1;
  memset(devices_, 0, sizeof(devices_));
  device_count_ = 0;
  unhandled_events_ = 0;
}

void Scanner::Start(unsigned now, bool inquire) {
  ScanObserver* observer = observer_;
  *this = Scanner(observer);
  inquire_on_start_ = inquire;
  credits_ = 1;  // A controller accepts one command after power-on/reset.
  Advance(kStageReset, now);
}

bool Scanner::Rescan(unsigned now) {
  if (stage_ != kStageDone) return false;
  memset(devices_, 0, sizeof(devices_));
  device_count_ = 0;
  name_index_ = -1;
  pending_opcode_ = 0;
  if (!credits_) credits_ = 1;
  Advance(kStageInquiry, now);
  return true;
}

void Scanner::Advance(unsigned next, unsigned now) {
  if (next == kStageInquiry) ++inquiries_;
  stage_ = next;
  command_ready_ = true;
  name_wait_ = false;
  // Covers waiting for command credits or for the transport to free up.
  deadline_ = now + kCommandTimeoutMs;
  deadline_armed_ = true;
}

void Scanner::Fail(unsigned failure, u16 opcode, u8 status) {
  if (finished()) return;
  unsigned failed_stage = stage_;
  stage_ = kStageFailed;
  command_ready_ = false;
  deadline_armed_ = false;
  if (observer_) observer_->OnFailed(failed_stage, failure, opcode, status);
}

void Scanner::Abort(unsigned failure, u8 status) {
  Fail(failure, pending_opcode_ ? pending_opcode_ : built_opcode_, status);
}

unsigned Scanner::NextCommand(u8* out, unsigned capacity) {
  if (finished() || !command_ready_ || pending_opcode_ || !credits_) return 0;
  u8 params[248];
  u8 length = 0;
  u16 opcode = 0;
  switch (stage_) {
    case kStageReset: opcode = kOpReset; break;
    case kStageReadVersion: opcode = kOpReadLocalVersion; break;
    case kStageReadAddress: opcode = kOpReadBdAddr; break;
    case kStageBufferSize: opcode = kOpReadBufferSize; break;
    case kStageEventMask:
      opcode = kOpSetEventMask;
      memcpy(params, kEventMask, 8);
      length = 8;
      break;
    case kStageInquiryMode:
      opcode = kOpWriteInquiryMode;
      params[0] = inquiry_mode_;
      length = 1;
      break;
    case kStageSimplePairing:
      opcode = kOpWriteSimplePairingMode;
      params[0] = 1;
      length = 1;
      break;
    case kStageLocalName: {
      opcode = kOpWriteLocalName;
      memset(params, 0, 248);
      const char* name = LocalName();
      memcpy(params, name, strlen(name));
      length = 248;
      break;
    }
    case kStageInquiry:
      opcode = kOpInquiry;
      memcpy(params, kGiac, 3);
      params[3] = kInquiryLength;
      params[4] = 0;  // Unlimited responses.
      length = 5;
      break;
    case kStageNames: {
      if (name_index_ < 0) return 0;
      const Device& d = devices_[name_index_];
      opcode = kOpRemoteNameRequest;
      memcpy(params, d.address, 6);
      params[6] = d.page_scan_repetition_mode;
      params[7] = 0;
      u16 offset = (u16)(d.clock_offset | 0x8000);  // Bit 15: offset valid.
      params[8] = (u8)(offset & 0xFF);
      params[9] = (u8)(offset >> 8);
      length = 10;
      break;
    }
    default:
      return 0;
  }
  unsigned n = BuildCommand(opcode, params, length, out, capacity);
  if (n) built_opcode_ = opcode;
  return n;
}

void Scanner::CommandSent(unsigned now) {
  if (finished() || !command_ready_ || !built_opcode_) return;
  pending_opcode_ = built_opcode_;
  command_ready_ = false;
  if (credits_) --credits_;
  deadline_ = now + kCommandTimeoutMs;
  deadline_armed_ = true;
}

void Scanner::Tick(unsigned now) {
  if (finished() || !deadline_armed_ || !Expired(now, deadline_)) return;
  if (pending_opcode_ || command_ready_) {
    Fail(kFailCommandTimeout, pending_opcode_ ? pending_opcode_ : built_opcode_, 0);
  } else if (stage_ == kStageInquiry) {
    Fail(kFailInquiryTimeout, kOpInquiry, 0);
  } else if (stage_ == kStageNames && name_wait_) {
    // The controller may still be paging; don't stack another request on
    // it. Report the timeout and finish with the names resolved so far.
    if (observer_) observer_->OnWarning(stage_, kOpRemoteNameRequest, 0xFF);
    if (name_index_ >= 0) devices_[name_index_].name_source = kNameFailed;
    stage_ = kStageDone;
    deadline_armed_ = false;
    if (observer_) observer_->OnComplete(devices_, device_count_);
  }
}

void Scanner::BeginNames(unsigned now) {
  name_index_ = -1;
  NextName(now);
}

void Scanner::NextName(unsigned now) {
  for (int i = name_index_ + 1; i < (int)device_count_; ++i) {
    if (devices_[i].name_source != kNameNone) continue;
    name_index_ = i;
    Advance(kStageNames, now);
    return;
  }
  stage_ = kStageDone;
  command_ready_ = false;
  deadline_armed_ = false;
  name_wait_ = false;
  if (observer_) observer_->OnComplete(devices_, device_count_);
}

bool Scanner::OnCommandComplete(const u8* p, unsigned n, unsigned now) {
  if (n < 3) { Fail(kFailMalformed, 0, 0); return false; }
  credits_ = p[0];
  u16 opcode = Le16(p + 1);
  if (!opcode) return true;  // Credit update only.
  if (opcode != pending_opcode_) { ++unhandled_events_; return true; }
  pending_opcode_ = 0;
  deadline_armed_ = false;
  const u8* r = p + 3;
  unsigned rn = n - 3;
  if (!rn) { Fail(kFailMalformed, opcode, 0); return false; }
  u8 status = r[0];
  switch (stage_) {
    case kStageReset:
      if (status) { Fail(kFailCommandStatus, opcode, status); return false; }
      Advance(kStageReadVersion, now);
      break;
    case kStageReadVersion:
      if (!status && rn >= 9) {
        LocalVersion v;
        v.hci_version = r[1];
        v.hci_revision = Le16(r + 2);
        v.lmp_version = r[4];
        v.manufacturer = Le16(r + 5);
        v.lmp_subversion = Le16(r + 7);
        if (observer_) observer_->OnLocalVersion(v);
      } else if (observer_) {
        observer_->OnWarning(stage_, opcode, status);
      }
      Advance(kStageReadAddress, now);
      break;
    case kStageReadAddress:
      if (status || rn < 7) {
        Fail(status ? kFailCommandStatus : kFailMalformed, opcode, status);
        return false;
      }
      memcpy(local_address_, r + 1, 6);
      if (observer_) observer_->OnLocalAddress(local_address_);
      Advance(kStageBufferSize, now);
      break;
    case kStageBufferSize:
      if (!status && rn >= 8) {
        unsigned mtu = Le16(r + 1), count = Le16(r + 4);
        if (mtu >= 27) acl_mtu_ = mtu;
        if (count) acl_buffers_ = count;
      } else if (observer_) {
        observer_->OnWarning(stage_, opcode, status);
      }
      Advance(kStageEventMask, now);
      break;
    case kStageEventMask:
      // Without the extended mask, standard inquiry results still arrive.
      if (status && observer_) observer_->OnWarning(stage_, opcode, status);
      Advance(kStageInquiryMode, now);
      break;
    case kStageInquiryMode:
      if (status) {
        if (observer_) observer_->OnWarning(stage_, opcode, status);
        if (inquiry_mode_ > 1) {
          --inquiry_mode_;  // Extended rejected: try "with RSSI".
          Advance(kStageInquiryMode, now);
          break;
        }
        // Fall through to inquiry using the controller's default mode.
      }
      Advance(kStageSimplePairing, now);
      break;
    case kStageSimplePairing:
      // Without SSP the controller falls back to legacy PIN pairing.
      if (status && observer_) observer_->OnWarning(stage_, opcode, status);
      Advance(kStageLocalName, now);
      break;
    case kStageLocalName:
      if (status && observer_) observer_->OnWarning(stage_, opcode, status);
      if (!inquire_on_start_) {
        stage_ = kStageDone;  // Controller ready; scanning waits for Rescan.
        deadline_armed_ = false;
        command_ready_ = false;
        break;
      }
      Advance(kStageInquiry, now);
      break;
    default:
      if (status) { Fail(kFailCommandStatus, opcode, status); return false; }
      ++unhandled_events_;
      break;
  }
  return true;
}

bool Scanner::OnCommandStatus(const u8* p, unsigned n, unsigned now) {
  if (n < 4) { Fail(kFailMalformed, 0, 0); return false; }
  u8 status = p[0];
  credits_ = p[1];
  u16 opcode = Le16(p + 2);
  if (!opcode) return true;
  if (opcode != pending_opcode_) { ++unhandled_events_; return true; }
  pending_opcode_ = 0;
  deadline_armed_ = false;
  if (stage_ == kStageInquiry) {
    if (status) { Fail(kFailCommandStatus, opcode, status); return false; }
    deadline_ = now + kInquiryLength * kInquiryUnitMs + kInquirySlackMs;
    deadline_armed_ = true;
    if (observer_) observer_->OnInquiryStarted(kInquiryLength * kInquiryUnitMs);
  } else if (stage_ == kStageNames) {
    if (status) {
      if (observer_) observer_->OnWarning(stage_, opcode, status);
      devices_[name_index_].name_source = kNameFailed;
      NextName(now);
    } else {
      name_wait_ = true;
      deadline_ = now + kNameTimeoutMs;
      deadline_armed_ = true;
    }
  } else {
    // Commands that answer with Command Complete only send Status on error.
    Fail(kFailCommandStatus, opcode, status);
    return false;
  }
  return true;
}

Device* Scanner::Upsert(const u8* address, bool* added) {
  *added = false;
  for (unsigned i = 0; i < device_count_; ++i)
    if (!memcmp(devices_[i].address, address, 6)) return &devices_[i];
  if (device_count_ == kMaxDevices) return 0;
  Device* d = &devices_[device_count_++];
  memset(d, 0, sizeof(*d));
  memcpy(d->address, address, 6);
  *added = true;
  return d;
}

void Scanner::OnInquiryResult(u8 code, const u8* p, unsigned n) {
  if (n < 1) return;
  unsigned count = p[0];
  unsigned record = 14;
  bool rssi_variant = false;  // Some controllers add a page-scan-mode byte.
  if (code == kEvInquiryResultWithRssi && count && n == 1 + count * 15) {
    record = 15;
    rssi_variant = true;
  }
  if (code == kEvExtendedInquiryResult) count = count ? 1 : 0;
  if (!count || n < 1 + count * record) return;
  for (unsigned i = 0; i < count; ++i) {
    const u8* r = p + 1 + i * record;
    unsigned cod_at = rssi_variant ? 9 : (code == kEvInquiryResult ? 9 : 8);
    bool added = false;
    Device* d = Upsert(r, &added);
    if (!d) continue;
    d->page_scan_repetition_mode = r[6];
    d->class_of_device = Le24(r + cod_at);
    d->clock_offset = (u16)(Le16(r + cod_at + 3) & 0x7FFF);
    if (code != kEvInquiryResult) {
      d->rssi = (signed char)r[cod_at + 5];
      d->has_rssi = true;
    }
    bool named = false;
    if (code == kEvExtendedInquiryResult && d->name_source != kNameRemote &&
        EirName(p + 15, n - 15, d->name, sizeof(d->name)) && d->name[0]) {
      named = d->name_source != kNameEir;
      d->name_source = kNameEir;
    }
    if (!observer_) continue;
    if (added) observer_->OnDeviceFound(*d);
    else if (named) observer_->OnDeviceNamed(*d);
  }
}

void Scanner::OnRemoteName(const u8* p, unsigned n, unsigned now) {
  if (n < 7) { Fail(kFailMalformed, kOpRemoteNameRequest, 0); return; }
  u8 status = p[0];
  Device* target = 0;
  for (unsigned i = 0; i < device_count_; ++i)
    if (!memcmp(devices_[i].address, p + 1, 6)) target = &devices_[i];
  if (target) {
    if (!status) {
      CopyName(p + 7, n - 7, target->name, sizeof(target->name));
      target->name_source = kNameRemote;
      if (observer_) observer_->OnDeviceNamed(*target);
    } else {
      target->name_source = kNameFailed;
      if (observer_) observer_->OnWarning(stage_, kOpRemoteNameRequest, status);
    }
  }
  if (name_wait_ && name_index_ >= 0 && target == &devices_[name_index_])
    NextName(now);
}

void Scanner::OnEvent(const u8* event, unsigned length, unsigned now) {
  if (finished() || length < 2 || length != 2u + event[1]) return;
  const u8* p = event + 2;
  unsigned n = event[1];
  switch (event[0]) {
    case kEvCommandComplete: OnCommandComplete(p, n, now); break;
    case kEvCommandStatus: OnCommandStatus(p, n, now); break;
    case kEvInquiryResult:
    case kEvInquiryResultWithRssi:
    case kEvExtendedInquiryResult:
      if (stage_ == kStageInquiry) OnInquiryResult(event[0], p, n);
      else ++unhandled_events_;
      break;
    case kEvInquiryComplete:
      if (stage_ != kStageInquiry || pending_opcode_) { ++unhandled_events_; break; }
      if (n >= 1 && p[0]) { Fail(kFailCommandStatus, kOpInquiry, p[0]); break; }
      deadline_armed_ = false;
      BeginNames(now);
      break;
    case kEvRemoteNameRequestComplete:
      if (stage_ == kStageNames) OnRemoteName(p, n, now);
      else ++unhandled_events_;
      break;
    case kEvHardwareError:
      Fail(kFailHardware, 0, n ? p[0] : 0);
      break;
    default:
      ++unhandled_events_;
      break;
  }
}

}  // namespace bt
