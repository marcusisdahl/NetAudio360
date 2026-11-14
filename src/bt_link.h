// SPDX-License-Identifier: GPL-3.0-or-later
// Outgoing ACL connection, authentication (Secure Simple Pairing "Just
// Works", legacy PIN fallback) and encryption for one remote device. Written
// from the Bluetooth Core Specification (Vol 4 Part E 7.1, 7.7 and Vol 3
// Part C 5.2.2); no third-party stack code. Platform-independent, like
// bt_hci, so host tests can drive it with canned events.
#ifndef USB_AUDIO360_BT_LINK_H_
#define USB_AUDIO360_BT_LINK_H_

#include "bt_hci.h"

namespace bt {

enum LinkOpcode {
  kOpCreateConnection = 0x0405,
  kOpDisconnect = 0x0406,
  kOpLinkKeyRequestReply = 0x040B,
  kOpLinkKeyRequestNegativeReply = 0x040C,
  kOpPinCodeRequestReply = 0x040D,
  kOpAuthenticationRequested = 0x0411,
  kOpSetConnectionEncryption = 0x0413,
  kOpIoCapabilityRequestReply = 0x042B,
  kOpUserConfirmationRequestReply = 0x042C,
  kOpUserPasskeyRequestNegativeReply = 0x042F
};

enum LinkEvent {
  kEvConnectionComplete = 0x03,
  kEvConnectionRequest = 0x04,
  kEvDisconnectionComplete = 0x05,
  kEvAuthenticationComplete = 0x06,
  kEvEncryptionChange = 0x08,
  kEvPinCodeRequest = 0x16,
  kEvLinkKeyRequest = 0x17,
  kEvLinkKeyNotification = 0x18,
  kEvIoCapabilityRequest = 0x31,
  kEvIoCapabilityResponse = 0x32,
  kEvUserConfirmationRequest = 0x33,
  kEvUserPasskeyRequest = 0x34,
  kEvSimplePairingComplete = 0x36
};

enum LinkState {
  kLinkIdle = 0,
  kLinkConnecting,      // Create_Connection sent; paging.
  kLinkAuthenticating,  // Authentication_Requested; pairing or key check.
  kLinkEncrypting,      // Set_Connection_Encryption.
  kLinkConnected,       // Authenticated and encrypted ACL link.
  kLinkDisconnecting
};

// Why the last attempt ended. Status bytes are the controller's HCI error
// codes (Core Vol 1 Part F), e.g. 0x04 page timeout, 0x05 authentication
// failure, 0x06 key missing, 0x13/0x16 remote/local disconnect.
enum LinkFailure {
  kLinkOk = 0,
  kLinkFailCommand = 1,   // Controller rejected a command.
  kLinkFailTimeout = 2,   // No progress before the deadline.
  kLinkFailConnect = 3,   // Connection Complete with an error.
  kLinkFailAuth = 4,      // Authentication Complete with an error.
  kLinkFailEncrypt = 5,   // Encryption Change with an error or disabled.
  kLinkFailClosed = 6,    // Disconnected (status = reason).
  kLinkFailHardware = 7,
  kLinkFailTransport = 8
};

const char* LinkStateName(unsigned state);
const char* LinkFailureName(unsigned failure);

class LinkObserver {
 public:
  virtual ~LinkObserver() {}
  // Stored key for this address, if any (16 bytes).
  virtual bool FindLinkKey(const u8* address, u8* key) = 0;
  // A new key from pairing; persist it (type per Core 7.7.24).
  virtual void OnLinkKey(const u8* address, const u8* key, u8 type) = 0;
  // The remote rejected our stored key (it was reset or forgot us).
  virtual void OnLinkKeyRejected(const u8* address) = 0;
  virtual void OnLinkState(unsigned state, const u8* address) = 0;
  virtual void OnLinkFailed(unsigned failure, u16 opcode, u8 status,
                            const u8* address) = 0;
};

class Link {
 public:
  static const unsigned kConnectTimeoutMs = 20000;   // Page + pairing.
  static const unsigned kCommandTimeoutMs = 5000;
  static const unsigned kDisconnectTimeoutMs = 5000;

  explicit Link(LinkObserver* observer);
  // Discards all state, e.g. after a controller reset or adapter removal.
  void Reset();
  // Starts connecting to a device found by inquiry (its page-scan mode and
  // clock offset speed up paging). Only from kLinkIdle.
  bool Connect(const Device& device, unsigned now);
  // Connects to a known address without inquiry data.
  bool Connect(const u8* address, unsigned now);
  // Disconnects (or abandons a connection attempt).
  bool Disconnect(unsigned now);

  unsigned NextCommand(u8* out, unsigned capacity);
  void CommandSent(unsigned now);
  void Abort(u8 status);  // The command transfer could not be submitted.
  void OnEvent(const u8* event, unsigned length, unsigned now);
  void Tick(unsigned now);

  unsigned state() const { return state_; }
  bool busy() const { return state_ != kLinkIdle; }
  const u8* address() const { return address_; }
  u16 handle() const { return handle_; }
  bool paired_now() const { return new_key_; }
  unsigned unhandled_events() const { return unhandled_; }

 private:
  struct Command {
    u16 opcode;
    u8 length;
    u8 params[23];
  };
  bool Enqueue(u16 opcode, const u8* params, u8 length);
  void SetState(unsigned state, unsigned now, unsigned timeout_ms);
  void Fail(unsigned failure, u16 opcode, u8 status, unsigned now);
  void Finish(unsigned failure, u16 opcode, u8 status);
  bool ForUs(const u8* address) const;
  bool ForHandle(const u8* p) const;
  void OnCommandComplete(const u8* p, unsigned n, unsigned now);
  void OnCommandStatus(const u8* p, unsigned n, unsigned now);

  LinkObserver* observer_;
  unsigned state_;
  u8 address_[6];
  u16 handle_;
  bool have_handle_;
  bool new_key_;
  bool used_stored_key_;
  u8 credits_;
  u16 pending_opcode_;
  bool sent_;            // queue_[0] is in flight.
  Command queue_[4];
  unsigned queued_;
  unsigned deadline_;
  bool deadline_armed_;
  unsigned command_deadline_;
  // Remembered so a failure reported later (e.g. on disconnect) keeps the
  // first cause.
  unsigned failure_;
  u16 failure_opcode_;
  u8 failure_status_;
  unsigned unhandled_;
};

// ---------------------------------------------------------------------------
// Paired devices and their link keys, kept as a small text file:
//   # comment
//   AA:BB:CC:DD:EE:FF <32 hex digits key> <key type> <name to end of line>
// Most recently paired first. The key is the 16 bytes as on the wire.

const unsigned kMaxPaired = 3;

struct PairedDevice {
  u8 address[6];
  u8 key[16];
  u8 key_type;
  char name[kMaxNameBytes];
};

class PairedStore {
 public:
  PairedStore() : count_(0) {}
  void Clear() { count_ = 0; }
  unsigned count() const { return count_; }
  const PairedDevice& at(unsigned i) const { return devices_[i]; }
  const PairedDevice* Find(const u8* address) const;
  // Adds or replaces, moving it to the front. When full the oldest is
  // dropped. A null or empty name keeps an existing one.
  void Put(const u8* address, const u8* key, u8 key_type, const char* name);
  bool Remove(const u8* address);
  // Returns bytes written (0 if it doesn't fit). Output is NUL-terminated.
  unsigned Format(char* out, unsigned capacity) const;
  // Replaces the contents. Returns false (and keeps nothing) if any
  // non-comment line is malformed.
  bool Parse(const char* text, unsigned length);

 private:
  PairedDevice devices_[kMaxPaired];
  unsigned count_;
};

}  // namespace bt

#endif  // USB_AUDIO360_BT_LINK_H_
