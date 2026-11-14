// SPDX-License-Identifier: GPL-3.0-or-later
// Portable Bluetooth HCI host layer for the USB transport (Bluetooth Core
// Specification, Vol 4 Part B "USB Transport Layer" and Vol 4 Part E "Host
// Controller Interface Functional Specification"). Written from the
// specification; no third-party Bluetooth stack code. Platform-independent so
// host tests can drive it with canned byte streams.
#ifndef USB_AUDIO360_BT_HCI_H_
#define USB_AUDIO360_BT_HCI_H_

#include <stddef.h>

namespace bt {

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

// ---------------------------------------------------------------------------
// USB descriptors

// Endpoints of the primary HCI interface (class E0/01/01, interface 0,
// alternate 0): interrupt IN carries events, bulk IN/OUT carry ACL data.
struct HciEndpoints {
  u8 interface_number;
  u8 event_address;
  u16 event_max_packet;
  u8 event_interval;
  u8 acl_in_address;
  u16 acl_in_max_packet;
  u8 acl_out_address;
  u16 acl_out_max_packet;
};

// Finds the primary HCI interface in a full configuration descriptor.
// Returns false unless exactly the three required endpoints are present.
bool FindHciEndpoints(const u8* configuration, size_t length,
                      HciEndpoints* out);

// ---------------------------------------------------------------------------
// Commands and events

enum Opcode {
  kOpInquiry = 0x0401,
  kOpRemoteNameRequest = 0x0419,
  kOpSetEventMask = 0x0C01,
  kOpReset = 0x0C03,
  kOpWriteInquiryMode = 0x0C45,
  kOpReadLocalVersion = 0x1001,
  kOpReadBdAddr = 0x1009
};

enum EventCode {
  kEvInquiryComplete = 0x01,
  kEvInquiryResult = 0x02,
  kEvRemoteNameRequestComplete = 0x07,
  kEvCommandComplete = 0x0E,
  kEvCommandStatus = 0x0F,
  kEvHardwareError = 0x10,
  kEvInquiryResultWithRssi = 0x22,
  kEvExtendedInquiryResult = 0x2F
};

const unsigned kMaxCommandBytes = 3 + 255;
const unsigned kMaxEventBytes = 2 + 255;

// Writes opcode (LE), parameter length and parameters. Returns total bytes.
unsigned BuildCommand(u16 opcode, const u8* params, u8 param_length,
                      u8* out, unsigned capacity);

// Reassembles events from interrupt-IN chunks of any size. An event is
// complete when 2 + its parameter-length byte have arrived.
class EventAssembler {
 public:
  EventAssembler() : have_(0), done_(false) {}
  void Reset() { have_ = 0; done_ = false; }
  // Consumes bytes up to and including the end of the next complete event.
  // Returns the number of bytes consumed. *complete is set when buffer()
  // holds a full event of length().
  size_t Push(const u8* data, size_t length, bool* complete);
  const u8* buffer() const { return buffer_; }
  unsigned length() const { return have_; }
  bool partial() const { return have_ != 0 && !done_; }

 private:
  u8 buffer_[kMaxEventBytes];
  unsigned have_;
  bool done_;
};

// Copies the local name from Extended Inquiry Response data (complete name
// 0x09 preferred over shortened name 0x08). Returns false if absent.
bool EirName(const u8* eir, size_t length, char* name, size_t capacity);

// Copies a UTF-8 name of at most source_length bytes, stopping at NUL, and
// truncating at a character boundary so the output is valid UTF-8.
void CopyName(const u8* source, size_t source_length, char* name,
              size_t capacity);

// Single-producer/single-consumer byte ring. The producer (USB completion)
// and consumer (worker) may run on different processors; barriers make the
// data visible before the index that publishes it.
#if defined(_XBOX)
#define BT_BARRIER() MemoryBarrier()  // From xtl.h; include it first.
#else
#define BT_BARRIER() __sync_synchronize()
#endif
template <unsigned kSize>
class ByteRing {
 public:
  ByteRing() : write_(0), read_(0), dropped_(0) {}
  // Producer only. All-or-nothing; a dropped chunk is counted.
  bool Write(const u8* data, unsigned length) {
    unsigned w = write_;
    BT_BARRIER();
    unsigned r = read_;
    if (length > kSize - (w - r)) { ++dropped_; return false; }
    for (unsigned i = 0; i < length; ++i) data_[(w + i) & (kSize - 1)] = data[i];
    BT_BARRIER();
    write_ = w + length;
    return true;
  }
  // Consumer only.
  unsigned Read(u8* out, unsigned capacity) {
    unsigned w = write_;
    BT_BARRIER();
    unsigned r = read_;
    unsigned n = w - r;
    if (n > capacity) n = capacity;
    for (unsigned i = 0; i < n; ++i) out[i] = data_[(r + i) & (kSize - 1)];
    BT_BARRIER();
    read_ = r + n;
    return n;
  }
  // Consumer only: discard everything published so far.
  void Clear() { unsigned w = write_; BT_BARRIER(); read_ = w; }
  unsigned dropped() const { return dropped_; }

 private:
  typedef char RequirePowerOfTwo[(kSize & (kSize - 1)) == 0 ? 1 : -1];
  u8 data_[kSize];
  volatile unsigned write_;
  volatile unsigned read_;
  volatile unsigned dropped_;
};

// ---------------------------------------------------------------------------
// Device discovery

const unsigned kMaxDevices = 16;
const unsigned kMaxNameBytes = 64;  // Including NUL; longer names truncated.

enum NameSource { kNameNone = 0, kNameEir = 1, kNameRemote = 2, kNameFailed = 3 };

struct Device {
  u8 address[6];  // Little-endian, as on the wire.
  u32 class_of_device;
  signed char rssi;
  bool has_rssi;
  u8 page_scan_repetition_mode;
  u16 clock_offset;
  u8 name_source;
  char name[kMaxNameBytes];
};

struct LocalVersion {
  u8 hci_version;
  u16 hci_revision;
  u8 lmp_version;
  u16 manufacturer;
  u16 lmp_subversion;
};

enum Stage {
  kStageIdle = 0,
  kStageReset,
  kStageReadVersion,
  kStageReadAddress,
  kStageEventMask,
  kStageInquiryMode,
  kStageInquiry,
  kStageNames,
  kStageDone,
  kStageFailed
};

enum Failure {
  kFailNone = 0,
  kFailCommandStatus = 1,   // Controller rejected a command (status != 0).
  kFailCommandTimeout = 2,  // No Command Complete/Status before deadline.
  kFailInquiryTimeout = 3,  // No Inquiry Complete before deadline.
  kFailMalformed = 4,       // Event shorter than its required parameters.
  kFailHardware = 5,        // Hardware Error event.
  kFailTransport = 6        // USB command transfer failed (status = 0).
};

const char* StageName(unsigned stage);
const char* FailureName(unsigned failure);

class ScanObserver {
 public:
  virtual ~ScanObserver() {}
  virtual void OnLocalVersion(const LocalVersion& version) = 0;
  virtual void OnLocalAddress(const u8* address) = 0;
  virtual void OnInquiryStarted(unsigned duration_ms) = 0;
  virtual void OnDeviceFound(const Device& device) = 0;
  virtual void OnDeviceNamed(const Device& device) = 0;
  // Non-fatal: the scan continues (e.g. a name request that failed).
  virtual void OnWarning(unsigned stage, u16 opcode, u8 status) = 0;
  virtual void OnComplete(const Device* devices, unsigned count) = 0;
  virtual void OnFailed(unsigned stage, unsigned failure, u16 opcode,
                        u8 status) = 0;
};

// Drives Reset -> Read_Local_Version -> Read_BD_ADDR -> Set_Event_Mask ->
// Write_Inquiry_Mode -> Inquiry -> Remote_Name_Request (for devices without
// an EIR name). One command in flight; honours Num_HCI_Command_Packets.
// Time is a caller-supplied millisecond tick (wrap-safe arithmetic).
class Scanner {
 public:
  static const unsigned kCommandTimeoutMs = 5000;
  static const unsigned kNameTimeoutMs = 15000;
  static const u8 kInquiryLength = 8;  // x 1.28 s = 10.24 s.

  explicit Scanner(ScanObserver* observer);
  void Start(unsigned now);
  // After a finished scan: run another inquiry without resetting the
  // controller. Keeps the local address; clears the device table.
  bool Rescan(unsigned now);
  // If a command may be sent now, writes it and returns its length (else 0).
  // The caller must call CommandSent once the transfer was accepted.
  unsigned NextCommand(u8* out, unsigned capacity);
  void CommandSent(unsigned now);
  // Abandons the scan, e.g. the command transfer could not be submitted.
  void Abort(unsigned failure, u8 status);
  void OnEvent(const u8* event, unsigned length, unsigned now);
  void Tick(unsigned now);

  unsigned stage() const { return stage_; }
  bool finished() const { return stage_ == kStageDone || stage_ == kStageFailed; }
  const u8* local_address() const { return local_address_; }
  const Device* devices() const { return devices_; }
  unsigned device_count() const { return device_count_; }
  unsigned unhandled_events() const { return unhandled_events_; }

 private:
  void Fail(unsigned failure, u16 opcode, u8 status);
  void Advance(unsigned next, unsigned now);
  void BeginNames(unsigned now);
  void NextName(unsigned now);
  bool OnCommandComplete(const u8* p, unsigned n, unsigned now);
  bool OnCommandStatus(const u8* p, unsigned n, unsigned now);
  void OnInquiryResult(u8 code, const u8* p, unsigned n);
  void OnRemoteName(const u8* p, unsigned n, unsigned now);
  Device* Upsert(const u8* address, bool* added);

  ScanObserver* observer_;
  unsigned stage_;
  u8 credits_;
  u16 pending_opcode_;   // Awaiting Complete/Status for this opcode.
  u16 built_opcode_;     // Last command returned by NextCommand.
  bool command_ready_;   // A command for the current stage is unsent.
  u8 inquiry_mode_;      // Requested mode; falls back on rejection.
  unsigned deadline_;
  bool deadline_armed_;
  int name_index_;       // Device awaiting Remote Name Request Complete.
  bool name_wait_;
  u8 local_address_[6];
  Device devices_[kMaxDevices];
  unsigned device_count_;
  unsigned unhandled_events_;
};

// Formats a little-endian address as "AA:BB:CC:DD:EE:FF" (18 bytes incl NUL).
void FormatAddress(const u8* address, char* out);

}  // namespace bt

#endif  // USB_AUDIO360_BT_HCI_H_
