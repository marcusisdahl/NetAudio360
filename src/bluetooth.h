// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <xtl.h>

#ifndef USB_AUDIO360_BLUETOOTH
#define USB_AUDIO360_BLUETOOTH 1
#endif

// Stage 1: a claimed USB Bluetooth HCI adapter is reset and runs one inquiry;
// results go to usb_audio360.log and UsbBtDiagnostic.

// USB domain (add/remove hooks). Only publish state; never block or log.
VOID BluetoothDeviceAttached(void* handle);
VOID BluetoothDeviceRemoved();
// Called after the kernel's add completion returned for the claimed adapter;
// records the device node and its default-endpoint slot in UsbBtProbe.
VOID BluetoothRecordAddComplete(void* handle);

// Snapshot for the Guide (any passive thread).
enum BluetoothUiStatus {
  kBluetoothNoAdapter = 0,
  kBluetoothStarting = 1,   // Adapter claimed, controller setup running.
  kBluetoothScanning = 2,   // Inquiry or name resolution in progress.
  kBluetoothReady = 3,      // Last scan finished; device list is final.
  kBluetoothError = 4,      // Adapter stopped; replug to retry.
  kBluetoothIdle = 5        // Adapter ready; no search run yet.
};
struct BluetoothUiDevice {
  BYTE address[6];          // Little-endian, as on the wire.
  DWORD class_of_device;
  LONG rssi;
  BOOL has_rssi;
  char name[64];            // UTF-8; empty while unknown.
};
enum BluetoothUiLink {
  kBluetoothLinkNone = 0,
  kBluetoothLinkConnecting = 1,  // Paging, pairing or encrypting.
  kBluetoothLinkConnected = 2,
  kBluetoothLinkDisconnecting = 3
};
struct BluetoothUiPaired {
  BYTE address[6];
  char name[64];            // UTF-8; may be empty.
};
struct BluetoothUiState {
  DWORD sequence;           // Changes whenever anything below changes.
  DWORD status;             // BluetoothUiStatus.
  BOOL address_valid;
  BYTE address[6];
  WORD manufacturer;
  DWORD error;
  DWORD device_count;
  BluetoothUiDevice devices[16];
  DWORD paired_count;
  BluetoothUiPaired paired[3];
  DWORD link;               // BluetoothUiLink for link_address.
  BYTE link_address[6];
  BOOL link_paired_now;     // The current link was just paired.
  DWORD link_result_count;  // Increments when an attempt ends.
  DWORD link_failure;       // bt::LinkFailure of the last attempt (0 = ok).
  DWORD link_status;        // HCI status/reason of the last attempt.
  BYTE result_address[6];
};
BOOL BluetoothGetUiState(BluetoothUiState* state);
// Starts a ~10 s search ("Pair new device"); the adapter never scans
// otherwise. Ignored while setup or another search is running.
VOID BluetoothRequestScan();
BOOL BluetoothAdapterPresent();
// Pairs with a device from the last search (by address), connects to or
// disconnects from a paired device, or forgets one. Ignored while the adapter
// is busy with something else; the UI state shows the outcome.
VOID BluetoothRequestPair(const BYTE* address);
VOID BluetoothRequestToggle(const BYTE* address);
VOID BluetoothRequestForget(const BYTE* address);

// Passive worker thread that owns all Bluetooth USB submissions.
DWORD WINAPI BluetoothWorker(void*);
