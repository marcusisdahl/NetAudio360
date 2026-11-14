// SPDX-License-Identifier: GPL-3.0-or-later
#include "bt_a2dp.h"

#include <string.h>

#include "bt_avrcp.h"
#include "bt_sdp.h"

namespace bt {

namespace {

u16 Le16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
void Put16(u8* p, unsigned v) { p[0] = (u8)(v & 0xFF); p[1] = (u8)(v >> 8); }

bool Expired(unsigned now, unsigned deadline) {
  return (int)(now - deadline) >= 0;
}

// L2CAP signalling codes (Core Vol 3 Part A 4).
enum {
  kCommandReject = 0x01, kConnectionRequest = 0x02, kConnectionResponse = 0x03,
  kConfigureRequest = 0x04, kConfigureResponse = 0x05,
  kDisconnectionRequest = 0x06, kDisconnectionResponse = 0x07,
  kEchoRequest = 0x08, kEchoResponse = 0x09,
  kInformationRequest = 0x0A, kInformationResponse = 0x0B
};
const u16 kSignalingCid = 0x0001;
const u16 kPsmAvdtp = 0x0019;
const u16 kPsmSdp = 0x0001;
const u16 kPsmAvctp = 0x0017;

// AVDTP signals and message types (AVDTP 8.4-8.5).
enum {
  kDiscover = 0x01, kGetCapabilities = 0x02, kSetConfiguration = 0x03,
  kGetConfiguration = 0x04, kReconfigure = 0x05, kOpen = 0x06, kStart = 0x07,
  kClose = 0x08, kSuspend = 0x09, kAbort = 0x0A, kSecurityControl = 0x0B,
  kGetAllCapabilities = 0x0C, kDelayReport = 0x0D
};
enum { kMsgCommand = 0, kMsgGeneralReject = 1, kMsgAccept = 2, kMsgReject = 3 };
enum { kCategoryTransport = 0x01, kCategoryCodec = 0x07 };
const u8 kMediaAudio = 0x00;
const u8 kCodecSbc = 0x00;

}  // namespace

// ---------------------------------------------------------------------------

unsigned AclAssembler::Push(const u8* data, unsigned length, bool* complete) {
  *complete = false;
  unsigned used = 0;
  while (used < length) {
    if (header_have_ < 4) {
      header_[header_have_++] = data[used++];
      if (header_have_ == 4) {
        payload_need_ = Le16(header_ + 2);
        payload_have_ = 0;
        if (payload_need_ > kMaxFrame) payload_need_ = kMaxFrame;  // Truncate.
        if (!payload_need_) header_have_ = 0;
      }
      continue;
    }
    unsigned take = payload_need_ - payload_have_;
    if (take > length - used) take = length - used;
    memcpy(payload_ + payload_have_, data + used, take);
    payload_have_ += take;
    used += take;
    if (payload_have_ < payload_need_) continue;
    u16 word = Le16(header_);
    header_have_ = 0;
    u16 handle = (u16)(word & 0x0FFF);
    u8 flags = (u8)((word >> 12) & 3);
    if (Payload(flags, payload_, payload_need_) && handle == handle_) {
      *complete = true;
      return used;
    }
    (void)handle;
  }
  return used;
}

bool AclAssembler::Payload(u8 flags, const u8* p, unsigned n) {
  u16 word = Le16(header_);
  if (flags != 1) {  // Start of an L2CAP frame (flushable or not).
    handle_ = (u16)(word & 0x0FFF);
    frame_have_ = 0;
    if (n < 2) { frame_need_ = 0; return false; }
    frame_need_ = 4u + Le16(p);
    if (frame_need_ > kMaxFrame) { frame_need_ = 0; return false; }
  } else if (!frame_need_) {
    return false;  // Continuation without a start.
  }
  unsigned room = frame_need_ - frame_have_;
  if (n > room) n = room;
  memcpy(frame_ + frame_have_, p, n);
  frame_have_ += n;
  if (frame_have_ < frame_need_) return false;
  frame_need_ = 0;
  return true;
}

// ---------------------------------------------------------------------------

const char* A2dpStateName(unsigned state) {
  static const char* names[] = {
    "idle", "signal-connect", "discover", "capabilities", "configure", "open",
    "media-connect", "start", "streaming", "suspended", "failed"
  };
  return state < sizeof(names) / sizeof(names[0]) ? names[state] : "unknown";
}

const char* A2dpFailureName(unsigned failure) {
  static const char* names[] = {
    "none", "timeout", "l2cap", "rejected", "no-sbc-sink", "closed", "queue"
  };
  return failure < sizeof(names) / sizeof(names[0]) ? names[failure] : "unknown";
}

A2dpSource::A2dpSource(A2dpObserver* observer) : observer_(observer) { Reset(); }

void A2dpSource::Reset() {
  state_ = kA2dpIdle;
  deadline_ = 0;
  deadline_armed_ = false;
  next_id_ = 1;
  next_label_ = 0;
  pending_label_ = 0xFF;
  pending_signal_ = 0;
  memset(&signal_, 0, sizeof(signal_));
  memset(&media_, 0, sizeof(media_));
  memset(&sdp_, 0, sizeof(sdp_));
  memset(&avctp_, 0, sizeof(avctp_));
  avctp_tried_ = false;
  volume_registered_ = false;
  avctp_label_ = 0;
  streaming_since_ = 0;
  remote_signal_mtu_ = 672;
  remote_media_mtu_ = 672;
  remote_sdp_mtu_ = 672;
  sdp_requests_ = 0;
  sink_count_ = sink_index_ = 0;
  acp_seid_ = 0;
  memset(sbc_caps_, 0, sizeof(sbc_caps_));
  memset(&config_, 0, sizeof(config_));
  sequence_ = 0;
  out_head_ = out_count_ = 0;
  unhandled_ = 0;
}

u8* A2dpSource::Begin(u16 cid, unsigned payload) {
  if (out_count_ == kQueue || 4 + payload > kSlotBytes) {
    return 0;
  }
  unsigned slot = (out_head_ + out_count_) % kQueue;
  u8* p = out_[slot];
  Put16(p, payload);
  Put16(p + 2, cid);
  return p + 4;
}

void A2dpSource::Commit(unsigned payload) {
  unsigned slot = (out_head_ + out_count_) % kQueue;
  out_length_[slot] = 4 + payload;
  ++out_count_;
}

const u8* A2dpSource::Output(unsigned* length) const {
  if (!out_count_) { *length = 0; return 0; }
  *length = out_length_[out_head_];
  return out_[out_head_];
}

void A2dpSource::PopOutput() {
  if (!out_count_) return;
  out_head_ = (out_head_ + 1) % kQueue;
  --out_count_;
}

void A2dpSource::SendSignal(u8 code, u8 id, const u8* data, unsigned n) {
  u8* p = Begin(kSignalingCid, 4 + n);
  if (!p) { Fail(kA2dpFailQueue, code); return; }
  p[0] = code;
  p[1] = id;
  Put16(p + 2, n);
  if (n) memcpy(p + 4, data, n);
  Commit(4 + n);
}

void A2dpSource::SendConfigRequest(Channel& c) {
  // Our receive MTU; everything else default (basic mode, no flush timeout).
  u8 d[8];
  Put16(d, c.remote_cid);
  Put16(d + 2, 0);  // Flags: no continuation.
  d[4] = 0x01;      // MTU option
  d[5] = 2;
  Put16(d + 6, kOurMtu);
  SendSignal(kConfigureRequest, next_id_++, d, sizeof(d));
  if (!next_id_) next_id_ = 1;
}

void A2dpSource::SendAvdtp(u8 message_type, u8 label, u8 signal,
                           const u8* data, unsigned n) {
  if (!signal_.connected) return;
  u8* p = Begin(signal_.remote_cid, 2 + n);
  if (!p) { Fail(kA2dpFailQueue, signal); return; }
  p[0] = (u8)((label << 4) | message_type);  // Single packet.
  p[1] = (u8)(signal & 0x3F);
  if (n) memcpy(p + 2, data, n);
  Commit(2 + n);
}

void A2dpSource::Command(u8 signal, const u8* data, unsigned n, unsigned now) {
  pending_label_ = next_label_;
  pending_signal_ = signal;
  next_label_ = (u8)((next_label_ + 1) & 0x0F);
  SendAvdtp(kMsgCommand, pending_label_, signal, data, n);
  deadline_ = now + kStepTimeoutMs;
  deadline_armed_ = true;
}

void A2dpSource::SetState(unsigned state, unsigned now) {
  if (state == kA2dpStreaming && state_ != kA2dpStreaming && !streaming_since_)
    streaming_since_ = now ? now : 1;
  state_ = state;
  deadline_ = now + kStepTimeoutMs;
  deadline_armed_ = state != kA2dpStreaming && state != kA2dpSuspended &&
                    state != kA2dpIdle && state != kA2dpFailed;
  if (observer_) observer_->OnA2dpState(state_);
}

void A2dpSource::Fail(unsigned failure, unsigned detail) {
  if (state_ == kA2dpFailed) return;
  state_ = kA2dpFailed;
  deadline_armed_ = false;
  if (observer_) {
    observer_->OnA2dpState(state_);
    observer_->OnA2dpFailed(failure, detail);
  }
}

bool A2dpSource::Start(unsigned now) {
  if (state_ != kA2dpIdle) return false;
  Reset();
  signal_.open_requested = true;
  u8 d[4];
  Put16(d, kPsmAvdtp);
  Put16(d + 2, kSignalCid);
  SetState(kA2dpSignalConnect, now);
  SendSignal(kConnectionRequest, next_id_++, d, sizeof(d));
  return true;
}

void A2dpSource::RegisterVolume() {
  u8* out = Begin(avctp_.remote_cid, 32);
  if (!out) return;
  avctp_label_ = (u8)((avctp_label_ + 1) & 0x0F);
  unsigned length = AvrcpRegisterVolume(avctp_label_, out, 32);
  Put16(out - 4, length);
  Commit(length);
  volume_registered_ = true;
}

void A2dpSource::ChannelReady(unsigned now) {
  if (avrcp_connected() && !volume_registered_) RegisterVolume();
  if (state_ == kA2dpSignalConnect && signal_.our_config_done &&
      signal_.their_config_done) {
    // Signalling channel up: find the headphones' audio sink endpoints.
    SetState(kA2dpDiscover, now);
    Command(kDiscover, 0, 0, now);
  } else if (state_ == kA2dpMediaConnect && media_.our_config_done &&
             media_.their_config_done) {
    SetState(kA2dpStart, now);
    u8 d[1] = {(u8)(acp_seid_ << 2)};
    Command(kStart, d, 1, now);
  }
}

void A2dpSource::OnFrame(const u8* frame, unsigned length, unsigned now) {
  if (length < 4) return;
  unsigned n = Le16(frame);
  u16 cid = Le16(frame + 2);
  if (n > length - 4) return;
  const u8* p = frame + 4;
  if (cid == kSignalingCid) {
    // A C-frame may hold several commands.
    while (n >= 4) {
      unsigned len = Le16(p + 2);
      if (4 + len > n) break;
      OnSignal(p, 4 + len, now);
      p += 4 + len;
      n -= 4 + len;
    }
  } else if (cid == kSignalCid && signal_.connected) {
    OnAvdtp(p, n, now);
  } else if (cid == kSdpCid && sdp_.connected) {
    OnSdp(p, n);
  } else if (cid == kAvctpCid && avctp_.connected) {
    OnAvctp(p, n);
  } else {
    // Media channel input (none expected for a source) or unknown CID.
    if (cid != kMediaCid) ++unhandled_;
  }
}

void A2dpSource::OnSignal(const u8* p, unsigned n, unsigned now) {
  u8 code = p[0], id = p[1];
  const u8* d = p + 4;
  unsigned len = n - 4;
  switch (code) {
    case kConnectionRequest: {
      if (len < 4) break;
      u16 psm = Le16(d), scid = Le16(d + 2);
      u8 r[8];
      Channel* c = 0;
      u16 local = 0;
      if (psm == kPsmAvdtp && !signal_.connected && !signal_.open_requested) {
        c = &signal_; local = kSignalCid;   // Headphones opened signalling.
        if (state_ == kA2dpIdle) SetState(kA2dpSignalConnect, now);
      } else if (psm == kPsmAvctp && !avctp_.connected && !avctp_.open_requested) {
        c = &avctp_; local = kAvctpCid;  // Headphones' remote control.
      } else if (psm == kPsmSdp && !sdp_.connected) {
        c = &sdp_; local = kSdpCid;  // Headphones look up our A2DP record.
        remote_sdp_mtu_ = 672;
      } else if (psm == kPsmAvdtp && signal_.connected && !media_.connected &&
                 !media_.open_requested && state_ == kA2dpMediaConnect) {
        c = &media_; local = kMediaCid;
      }
      Put16(r, c ? local : 0);
      Put16(r + 2, scid);
      Put16(r + 4, c ? 0x0000 : 0x0002);  // Success / PSM not supported.
      Put16(r + 6, 0);
      SendSignal(kConnectionResponse, id, r, sizeof(r));
      if (c) {
        c->remote_cid = scid;
        c->connected = true;
        SendConfigRequest(*c);
      }
      break;
    }
    case kConnectionResponse: {
      if (len < 8) break;
      u16 dcid = Le16(d), scid = Le16(d + 2), result = Le16(d + 4);
      Channel* c = ChannelFor(scid);
      if (!c || !c->open_requested || c->connected) { ++unhandled_; break; }
      if (result == 0x0001) break;  // Pending: wait for the final response.
      if (result != 0 && c == &avctp_) {  // Optional: audio keeps playing.
        memset(&avctp_, 0, sizeof(avctp_));
        break;
      }
      if (result != 0) { Fail(kA2dpFailL2cap, result); break; }
      c->remote_cid = dcid;
      c->connected = true;
      SendConfigRequest(*c);
      break;
    }
    case kConfigureRequest: {
      if (len < 4) break;
      u16 dcid = Le16(d);
      Channel* c = ChannelFor(dcid);
      u8 r[6];
      if (!c || !c->connected) {
        // Invalid CID: Command Reject, reason 0x0002 with the CIDs.
        u8 j[6];
        Put16(j, 0x0002);
        Put16(j + 2, dcid);
        Put16(j + 4, 0);
        SendSignal(kCommandReject, id, j, sizeof(j));
        break;
      }
      // Accept everything; remember the MTU they can receive.
      for (unsigned at = 4; at + 2 <= len;) {
        u8 type = d[at] & 0x7F, olen = d[at + 1];
        if (at + 2 + olen > len) break;
        if (type == 0x01 && olen >= 2) {
          u16 mtu = Le16(d + at + 2);
          if (c == &signal_) remote_signal_mtu_ = mtu;
          else if (c == &sdp_) remote_sdp_mtu_ = mtu;
          else remote_media_mtu_ = mtu;
        }
        at += 2 + olen;
      }
      Put16(r, c->remote_cid);
      Put16(r + 2, 0);
      Put16(r + 4, 0);  // Success
      SendSignal(kConfigureResponse, id, r, sizeof(r));
      c->their_config_done = true;
      ChannelReady(now);
      break;
    }
    case kConfigureResponse: {
      if (len < 6) break;
      u16 scid = Le16(d), result = Le16(d + 4);
      Channel* c = ChannelFor(scid);
      if (!c) { ++unhandled_; break; }
      if (result == 0x0004) break;  // Pending.
      if (result != 0 && c == &avctp_) break;  // Leave remote control unused.
      if (result != 0) { Fail(kA2dpFailL2cap, 0x100 | result); break; }
      c->our_config_done = true;
      ChannelReady(now);
      break;
    }
    case kDisconnectionRequest: {
      if (len < 4) break;
      u16 dcid = Le16(d), scid = Le16(d + 2);
      u8 r[4];
      Put16(r, dcid);
      Put16(r + 2, scid);
      SendSignal(kDisconnectionResponse, id, r, sizeof(r));
      if (dcid == kSdpCid) {  // Query done; not part of the stream.
        memset(&sdp_, 0, sizeof(sdp_));
        break;
      }
      if (dcid == kAvctpCid) {  // Remote control closed; audio continues.
        memset(&avctp_, 0, sizeof(avctp_));
        break;
      }
      if (dcid == kSignalCid || dcid == kMediaCid) {
        Channel& c = dcid == kSignalCid ? signal_ : media_;
        memset(&c, 0, sizeof(c));
        if (state_ != kA2dpIdle) Fail(kA2dpFailClosed, dcid);
      }
      break;
    }
    case kEchoRequest:
      SendSignal(kEchoResponse, id, d, len);
      break;
    case kInformationRequest: {
      if (len < 2) break;
      u16 type = Le16(d);
      u8 r[12];
      Put16(r, type);
      if (type == 0x0002) {         // Extended features: none.
        Put16(r + 2, 0);
        memset(r + 4, 0, 4);
        SendSignal(kInformationResponse, id, r, 8);
      } else if (type == 0x0003) {  // Fixed channels: signalling only.
        Put16(r + 2, 0);
        memset(r + 4, 0, 8);
        r[4] = 0x02;
        SendSignal(kInformationResponse, id, r, 12);
      } else {
        Put16(r + 2, 0x0001);       // Not supported.
        SendSignal(kInformationResponse, id, r, 4);
      }
      break;
    }
    case kCommandReject:
    case kDisconnectionResponse:
    case kEchoResponse:
    case kInformationResponse:
      break;
    default: {
      u8 r[2];
      Put16(r, 0x0000);  // Command not understood.
      SendSignal(kCommandReject, id, r, sizeof(r));
      break;
    }
  }
}

A2dpSource::Channel* A2dpSource::ChannelFor(u16 local_cid) {
  if (local_cid == kSignalCid) return &signal_;
  if (local_cid == kMediaCid) return &media_;
  if (local_cid == kSdpCid) return &sdp_;
  if (local_cid == kAvctpCid) return &avctp_;
  return 0;
}

void A2dpSource::OnSdp(const u8* p, unsigned n) {
  ++sdp_requests_;
  unsigned capacity = remote_sdp_mtu_;
  if (capacity > kSlotBytes - 4) capacity = kSlotBytes - 4;
  u8* out = Begin(sdp_.remote_cid, capacity);
  if (!out) { Fail(kA2dpFailQueue, 0x5D); return; }
  unsigned length = SdpHandle(p, n, out, capacity);
  if (!length) return;  // Nothing committed; the slot stays free.
  Put16(out - 4, length);
  Commit(length);
}

void A2dpSource::OnAvctp(const u8* p, unsigned n) {
  unsigned capacity = 64;
  u8* out = Begin(avctp_.remote_cid, capacity);
  if (!out) return;  // Queue full: drop the reply; the headset retries.
  u8 volume = 0;
  int response = AvrcpVolumeResponse(p, n, &volume);
  if (response) {
    if (response != 3 && observer_) observer_->OnAvrcpVolume(volume, response == 2);
    if (response == 2) {
      RegisterVolume();  // Our slot is still free: Begin above is unused.
      return;
    }
    return;
  }
  u8 pressed = 0;
  unsigned length = AvrcpHandle(p, n, out, capacity, &pressed);
  if (length) {
    Put16(out - 4, length);
    Commit(length);
  }
  if (pressed && observer_) observer_->OnAvrcpKey(pressed);
}

void A2dpSource::WriteOurCapabilities(u8* out, unsigned* n) const {
  // Media transport + SBC: 44.1/48 kHz, all channel modes, 4-16 blocks,
  // 8 subbands, both allocations, bitpool 2-53.
  const u8 caps[] = {kCategoryTransport, 0, kCategoryCodec, 6,
                     (u8)(kMediaAudio << 4), kCodecSbc, 0x3F, 0xF5, 2, 53};
  memcpy(out, caps, sizeof(caps));
  *n = sizeof(caps);
}

void A2dpSource::OnAvdtp(const u8* p, unsigned n, unsigned now) {
  if (n < 2) return;
  u8 label = (u8)(p[0] >> 4);
  u8 packet_type = (u8)((p[0] >> 2) & 3);
  u8 message_type = (u8)(p[0] & 3);
  if (packet_type != 0) { ++unhandled_; return; }  // Fragmented: not used.
  u8 signal = (u8)(p[1] & 0x3F);
  if (message_type == kMsgCommand) {
    OnAvdtpCommand(label, signal, p + 2, n - 2, now);
  } else if (label == pending_label_) {
    pending_label_ = 0xFF;
    OnAvdtpResponse(message_type, signal, p + 2, n - 2, now);
  } else {
    ++unhandled_;
  }
}

void A2dpSource::OnAvdtpCommand(u8 label, u8 signal, const u8*, unsigned n,
                                unsigned now) {
  u8 r[16];
  unsigned rn = 0;
  switch (signal) {
    case kDiscover:
      r[0] = (u8)((kOurSeid << 2) | (state_ >= kA2dpConfigure ? 0x02 : 0));
      r[1] = (u8)(kMediaAudio << 4);  // TSEP 0 = source.
      SendAvdtp(kMsgAccept, label, signal, r, 2);
      return;
    case kGetCapabilities:
    case kGetAllCapabilities:
      WriteOurCapabilities(r, &rn);
      SendAvdtp(kMsgAccept, label, signal, r, rn);
      return;
    case kStart:
      SendAvdtp(kMsgAccept, label, signal, 0, 0);
      if (state_ == kA2dpSuspended) SetState(kA2dpStreaming, now);
      return;
    case kSuspend:
      SendAvdtp(kMsgAccept, label, signal, 0, 0);
      if (state_ == kA2dpStreaming) SetState(kA2dpSuspended, now);
      return;
    case kClose:
    case kAbort:
      SendAvdtp(kMsgAccept, label, signal, 0, 0);
      Fail(kA2dpFailClosed, signal);
      return;
    case kDelayReport:
    case kSecurityControl:
      SendAvdtp(kMsgAccept, label, signal, 0, 0);
      return;
    case kGetConfiguration:
    case kSetConfiguration:
    case kReconfigure:
    case kOpen:
      // We are the initiator; reject role reversal. Error 0x31: bad state.
      if (n >= 1 && signal != kOpen) { r[0] = 0; r[1] = 0x31; rn = 2; }
      else { r[0] = 0x31; rn = 1; }
      SendAvdtp(kMsgReject, label, signal, r, rn);
      return;
    default:
      SendAvdtp(kMsgGeneralReject, label, signal, 0, 0);
      ++unhandled_;
      return;
  }
}

void A2dpSource::NextCapabilities(unsigned now) {
  if (sink_index_ >= sink_count_) { Fail(kA2dpFailNoSbcSink, sink_count_); return; }
  u8 d[1] = {(u8)(sinks_[sink_index_] << 2)};
  Command(kGetCapabilities, d, 1, now);
}

bool A2dpSource::ChooseConfig(const u8* c, unsigned n) {
  if (n < 4) return false;
  SbcConfig cfg;
  if (c[0] & 0x10) cfg.frequency = kSbc48k;  // Matches the console mix.
  else return false;
  if (c[0] & 0x01) cfg.channel_mode = kSbcJoint;
  else if (c[0] & 0x02) cfg.channel_mode = kSbcStereo;
  else if (c[0] & 0x04) cfg.channel_mode = kSbcDual;
  else if (c[0] & 0x08) cfg.channel_mode = kSbcMono;
  else return false;
  if (c[1] & 0x10) cfg.blocks = 16;
  else if (c[1] & 0x20) cfg.blocks = 12;
  else if (c[1] & 0x40) cfg.blocks = 8;
  else if (c[1] & 0x80) cfg.blocks = 4;
  else return false;
  if (!(c[1] & 0x04)) return false;  // 8 subbands only.
  cfg.allocation = (c[1] & 0x01) ? kSbcLoudness : kSbcSnr;
  if (!(c[1] & 0x03)) return false;
  unsigned min_pool = c[2], max_pool = c[3];
  unsigned pool = max_pool < 53 ? max_pool : 53;
  if (pool < min_pool || pool < 2) return false;
  cfg.bitpool = pool;
  SbcEncoder probe;
  if (!probe.Configure(cfg)) return false;
  config_ = cfg;
  sbc_caps_[0] = (u8)((cfg.frequency == kSbc48k ? 0x10 : 0x20) |
                      (cfg.channel_mode == kSbcJoint ? 0x01 :
                       cfg.channel_mode == kSbcStereo ? 0x02 :
                       cfg.channel_mode == kSbcDual ? 0x04 : 0x08));
  sbc_caps_[1] = (u8)((cfg.blocks == 16 ? 0x10 : cfg.blocks == 12 ? 0x20 :
                       cfg.blocks == 8 ? 0x40 : 0x80) | 0x04 |
                      (cfg.allocation == kSbcLoudness ? 0x01 : 0x02));
  sbc_caps_[2] = (u8)pool;  // Fixed bitpool: min = max.
  sbc_caps_[3] = (u8)pool;
  return true;
}

void A2dpSource::OnAvdtpResponse(u8 type, u8 signal, const u8* p, unsigned n,
                                 unsigned now) {
  deadline_armed_ = false;
  if (type != kMsgAccept) {
    unsigned error = n ? p[n - 1] : 0;
    if (signal == kGetCapabilities && state_ == kA2dpCapabilities) {
      ++sink_index_;
      NextCapabilities(now);
      return;
    }
    Fail(kA2dpFailRejected, (signal << 8) | error);
    return;
  }
  switch (signal) {
    case kDiscover: {
      if (state_ != kA2dpDiscover) break;
      sink_count_ = 0;
      for (unsigned i = 0; i + 1 < n && sink_count_ < 8; i += 2) {
        u8 seid = (u8)(p[i] >> 2);
        bool in_use = (p[i] & 0x02) != 0;
        u8 media = (u8)(p[i + 1] >> 4);
        bool sink = (p[i + 1] & 0x08) != 0;
        if (!in_use && media == kMediaAudio && sink) sinks_[sink_count_++] = seid;
      }
      sink_index_ = 0;
      SetState(kA2dpCapabilities, now);
      NextCapabilities(now);
      break;
    }
    case kGetCapabilities: {
      if (state_ != kA2dpCapabilities) break;
      bool ok = false;
      for (unsigned at = 0; at + 2 <= n;) {
        u8 category = p[at], len = p[at + 1];
        if (at + 2 + len > n) break;
        if (category == kCategoryCodec && len >= 6 &&
            (p[at + 2] >> 4) == kMediaAudio && p[at + 3] == kCodecSbc)
          ok = ChooseConfig(p + at + 4, len - 2);
        at += 2 + len;
      }
      if (!ok) { ++sink_index_; NextCapabilities(now); break; }
      acp_seid_ = sinks_[sink_index_];
      SetState(kA2dpConfigure, now);
      u8 d[2 + 2 + 8] = {(u8)(acp_seid_ << 2), (u8)(kOurSeid << 2),
                         kCategoryTransport, 0, kCategoryCodec, 6,
                         (u8)(kMediaAudio << 4), kCodecSbc,
                         sbc_caps_[0], sbc_caps_[1], sbc_caps_[2], sbc_caps_[3]};
      Command(kSetConfiguration, d, sizeof(d), now);
      break;
    }
    case kSetConfiguration: {
      if (state_ != kA2dpConfigure) break;
      if (observer_) observer_->OnA2dpConfigured(config_);
      SetState(kA2dpOpen, now);
      u8 d[1] = {(u8)(acp_seid_ << 2)};
      Command(kOpen, d, 1, now);
      break;
    }
    case kOpen: {
      if (state_ != kA2dpOpen) break;
      // The initiator opens the transport channel next.
      SetState(kA2dpMediaConnect, now);
      media_.open_requested = true;
      u8 d[4];
      Put16(d, kPsmAvdtp);
      Put16(d + 2, kMediaCid);
      SendSignal(kConnectionRequest, next_id_++, d, sizeof(d));
      if (!next_id_) next_id_ = 1;
      break;
    }
    case kStart:
      if (state_ == kA2dpStart) SetState(kA2dpStreaming, now);
      break;
    default:
      break;
  }
}

bool A2dpSource::SendMedia(const u8* frames, unsigned bytes,
                           unsigned frame_count, u32 timestamp) {
  if (state_ != kA2dpStreaming || !media_.connected || !frame_count ||
      frame_count > 15)
    return false;
  unsigned payload = 12 + 1 + bytes;
  if (payload > remote_media_mtu_) return false;
  u8* p = Begin(media_.remote_cid, payload);
  if (!p) return false;
  p[0] = 0x80;  // RTP version 2
  p[1] = 0x60;  // Payload type 96 (dynamic), no marker.
  p[2] = (u8)(sequence_ >> 8);
  p[3] = (u8)(sequence_ & 0xFF);
  ++sequence_;
  p[4] = (u8)(timestamp >> 24);
  p[5] = (u8)(timestamp >> 16);
  p[6] = (u8)(timestamp >> 8);
  p[7] = (u8)timestamp;
  p[8] = 0; p[9] = 0; p[10] = 0; p[11] = 1;  // SSRC
  p[12] = (u8)frame_count;  // Not fragmented; frame count in the low bits.
  memcpy(p + 13, frames, bytes);
  Commit(payload);
  return true;
}

void A2dpSource::Tick(unsigned now) {
  if (deadline_armed_ && Expired(now, deadline_))
    Fail(kA2dpFailTimeout, state_);
  // Many headphones connect AVRCP themselves; if they have not shortly after
  // the stream starts, open it so their volume keys reach us.
  if (state_ == kA2dpStreaming && !avctp_tried_ && !avctp_.connected &&
      !avctp_.open_requested && Expired(now, streaming_since_ + kAvctpDelayMs) &&
      free_slots() >= 2) {
    avctp_tried_ = true;
    avctp_.open_requested = true;
    u8 d[4];
    Put16(d, kPsmAvctp);
    Put16(d + 2, kAvctpCid);
    SendSignal(kConnectionRequest, next_id_++, d, sizeof(d));
    if (!next_id_) next_id_ = 1;
  }
}

}  // namespace bt
