// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <xtl.h>

// Stage 1: a claimed USB Bluetooth HCI adapter is reset and runs one inquiry;
// results go to usb_audio360.log and UsbBtDiagnostic.

// USB domain (add/remove hooks). Only publish state; never block or log.
VOID BluetoothDeviceAttached(void* handle);
VOID BluetoothDeviceRemoved();

// Passive worker thread that owns all Bluetooth USB submissions.
DWORD WINAPI BluetoothWorker(void*);
