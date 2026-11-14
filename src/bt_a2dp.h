// SPDX-License-Identifier: GPL-3.0-or-later
// A2DP source over one ACL link: L2CAP basic mode channels (Core Vol 3 Part
// A), AVDTP signalling (AVDTP 1.3) and media packets (A2DP 1.3, SBC). Written
// from the Bluetooth specifications; no third-party stack code.
// Platform-independent: the caller moves L2CAP frames in and out of HCI ACL
// packets and feeds SBC frames.
#ifndef USB_AUDIO360_BT_A2DP_H_
#define USB_AUDIO360_BT_A2DP_H_

#include "bt_hci.h"
#include "bt_sbc.h"

namespace bt {

// Reassembles HCI ACL data packets (Core Vol 4 Part E 5.4.2) from bulk-IN
// bytes, then L2CAP frames from start/continuation fragments.
class AclAssembler {
 public:
  static const unsigned kMaxFrame = 1024;
  AclAssembler() { Reset(); }
  void Reset() { header_have_ = 0; payload_have_ = 0; frame_have_ = 0; frame_need_ = 0; }
  // Consumes bytes; returns how many. *complete: frame() holds one L2CAP
  // frame (basic header included) of frame_length() for handle().
  unsigned Push(const u8* data, unsigned length, bool* complete);
  const u8* frame() const { return frame_; }
  unsigned frame_length() const { return frame_have_; }
  u16 handle() const { return handle_; }

 private:
  bool Payload(u8 flags, const u8* p, unsigned n);
  u8 header_[4];
  unsigned header_have_;
  unsigned payload_need_, payload_have_;
  u8 payload_[kMaxFrame];
  u16 handle_;
  u8 frame_[kMaxFrame];
  unsigned frame_have_, frame_need_;
};

enum A2dpState {
  kA2dpIdle = 0,
  kA2dpSignalConnect,  // L2CAP channel for AVDTP signalling.
  kA2dpDiscover,
  kA2dpCapabilities,
  kA2dpConfigure,
  kA2dpOpen,
  kA2dpMediaConnect,   // L2CAP channel for media.
  kA2dpStart,
  kA2dpStreaming,
  kA2dpSuspended,      // The headphones paused the stream.
  kA2dpFailed
};

enum A2dpFailure {
  kA2dpOk = 0,
  kA2dpFailTimeout = 1,
  kA2dpFailL2cap = 2,      // Connection/configuration refused (status = result).
  kA2dpFailRejected = 3,   // AVDTP command rejected (status = error code).
  kA2dpFailNoSbcSink = 4,  // No SBC audio sink endpoint we can use.
  kA2dpFailClosed = 5,     // Remote closed the signalling or media channel.
  kA2dpFailQueue = 6
};

const char* A2dpStateName(unsigned state);
const char* A2dpFailureName(unsigned failure);

class A2dpObserver {
 public:
  virtual ~A2dpObserver() {}
  virtual void OnA2dpState(unsigned state) = 0;
  virtual void OnA2dpFailed(unsigned failure, unsigned detail) = 0;
  // Streaming configuration chosen for the encoder.
  virtual void OnA2dpConfigured(const SbcConfig& config) = 0;
  // A remote-control key from the headphones (AVRCP PASS THROUGH, pressed).
  virtual void OnAvrcpKey(unsigned operation) { (void)operation; }
};

class A2dpSource {
 public:
  static const unsigned kStepTimeoutMs = 10000;
  static const u16 kOurMtu = 1000;
  static const u16 kSignalCid = 0x0040;
  static const u16 kMediaCid = 0x0041;
  static const u16 kSdpCid = 0x0042;  // Headphones query our SDP record.
  static const u16 kAvctpCid = 0x0043;  // AVRCP remote control.
  static const unsigned kAvctpDelayMs = 1500;  // Then we open it ourselves.
  static const u8 kOurSeid = 1;

  explicit A2dpSource(A2dpObserver* observer);
  void Reset();
  // Starts the stream setup on an authenticated, encrypted link.
  bool Start(unsigned now);
  // Incoming L2CAP frame (basic header included).
  void OnFrame(const u8* frame, unsigned length, unsigned now);
  void Tick(unsigned now);

  // Outgoing L2CAP frames, oldest first.
  bool HasOutput() const { return out_count_ != 0; }
  const u8* Output(unsigned* length) const;
  void PopOutput();

  unsigned state() const { return state_; }
  bool streaming() const { return state_ == kA2dpStreaming; }
  const SbcConfig& config() const { return config_; }
  // Largest media payload (RTP header included) the remote accepts.
  u16 media_mtu() const { return remote_media_mtu_; }
  // Queues one media packet: RTP header, SBC payload header, frames.
  bool SendMedia(const u8* frames, unsigned bytes, unsigned frame_count,
                 u32 timestamp);
  unsigned free_slots() const { return kQueue - out_count_; }
  unsigned unhandled() const { return unhandled_; }
  unsigned sdp_requests() const { return sdp_requests_; }
  bool avrcp_connected() const { return avctp_.connected && avctp_.our_config_done && avctp_.their_config_done; }

 private:
  static const unsigned kQueue = 8;
  static const unsigned kSlotBytes = 1100;
  struct Channel {
    bool open_requested, local_cid_valid;
    u16 remote_cid;
    bool our_config_done, their_config_done;
    bool connected;  // Connection response success received/sent.
  };
  u8* Begin(u16 cid, unsigned payload);
  void Commit(unsigned payload);
  void SendSignal(u8 code, u8 id, const u8* data, unsigned n);
  void SendConfigRequest(Channel& c);
  void SendAvdtp(u8 message_type, u8 label, u8 signal, const u8* data, unsigned n);
  void Command(u8 signal, const u8* data, unsigned n, unsigned now);
  void SetState(unsigned state, unsigned now);
  void Fail(unsigned failure, unsigned detail);
  void OnSignal(const u8* p, unsigned n, unsigned now);
  void OnAvdtp(const u8* p, unsigned n, unsigned now);
  void OnAvdtpCommand(u8 label, u8 signal, const u8* p, unsigned n, unsigned now);
  void OnAvdtpResponse(u8 type, u8 signal, const u8* p, unsigned n, unsigned now);
  void NextCapabilities(unsigned now);
  bool ChooseConfig(const u8* codec, unsigned n);
  void ChannelReady(unsigned now);
  void WriteOurCapabilities(u8* out, unsigned* n) const;
  Channel* ChannelFor(u16 local_cid);
  void OnSdp(const u8* p, unsigned n);
  void OnAvctp(const u8* p, unsigned n);

  A2dpObserver* observer_;
  unsigned state_;
  unsigned deadline_;
  bool deadline_armed_;
  u8 next_id_;
  u8 next_label_;
  u8 pending_label_;
  u8 pending_signal_;
  Channel signal_, media_, sdp_, avctp_;
  bool avctp_tried_;
  unsigned streaming_since_;
  u16 remote_signal_mtu_, remote_media_mtu_, remote_sdp_mtu_;
  unsigned sdp_requests_;
  // Sink endpoints from DISCOVER.
  u8 sinks_[8];
  unsigned sink_count_, sink_index_;
  u8 acp_seid_;
  u8 sbc_caps_[4];
  SbcConfig config_;
  u16 sequence_;
  u8 out_[kQueue][kSlotBytes];
  unsigned out_length_[kQueue];
  unsigned out_head_, out_count_;
  unsigned unhandled_;
};

}  // namespace bt

#endif  // USB_AUDIO360_BT_A2DP_H_
