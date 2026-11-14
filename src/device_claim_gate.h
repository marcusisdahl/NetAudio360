// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef USB_AUDIO360_DEVICE_CLAIM_GATE_H_
#define USB_AUDIO360_DEVICE_CLAIM_GATE_H_

namespace usb_transport {

// This state machine is serialized by the USB DPC domain. It deliberately
// supports one claimed interface, either a UAC playback interface or a
// Bluetooth HCI interface: additional interfaces follow the kernel's normal
// unsupported-device path without touching plugin state.
class DeviceClaimGate {
 public:
  enum Kind { kNone = 0, kAudio = 1, kBluetooth = 2 };

  DeviceClaimGate() : state_(kIdle), handle_(0), kind_(kNone) {}

  bool available() const { return state_ == kIdle; }

  bool Activate(void* handle, Kind kind = kAudio) {
    if (state_ != kIdle || !handle || kind == kNone) return false;
    handle_ = handle;
    kind_ = kind;
    state_ = kActive;
    return true;
  }

  // Kind of the active or draining claim; kNone while idle.
  Kind kind() const { return kind_; }

  bool BeginRemoval(void* handle) {
    if (state_ != kActive || handle != handle_) return false;
    state_ = kDraining;
    return true;
  }

  bool CancelActivation(void* handle) {
    if (state_ != kActive || handle != handle_) return false;
    handle_ = 0;
    kind_ = kNone;
    state_ = kIdle;
    return true;
  }

  bool CompleteRemoval() {
    if (state_ != kDraining) return false;
    handle_ = 0;
    kind_ = kNone;
    state_ = kIdle;
    return true;
  }

  bool active(void* handle) const {
    return state_ == kActive && handle == handle_;
  }

  bool draining() const { return state_ == kDraining; }

 private:
  enum State { kIdle, kActive, kDraining };
  State state_;
  void* handle_;
  Kind kind_;
};

}  // namespace usb_transport

#endif  // USB_AUDIO360_DEVICE_CLAIM_GATE_H_
