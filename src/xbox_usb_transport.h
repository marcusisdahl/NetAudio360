// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "audio.h"

BOOL UsbTransportInitialize(const AudioHostApi* api);
// Attach/remove are called from the existing USB add/remove hooks.
BOOL UsbTransportAttach(void* handle);
typedef LONG (*UsbRemoveCompleteRoutine)(void* handle);
typedef void (*UsbRearmCompleteRoutine)();
BOOL UsbTransportDetach(void* handle, UsbRemoveCompleteRoutine remove_complete,
                        UsbRearmCompleteRoutine rearm_complete);
// Passive caller after physical removal: succeeds only after every submitted
// transfer/cancellation has completed in the USB domain.
BOOL UsbTransportRearm();
// Worker-only entry points; raw USB operations run on the verified USB DPC CPU.
LONG UsbTransportOpenDefault(void* handle, DWORD* endpoint);
// Endpoint transfer type passed to the kernel open routine (USB bmAttributes
// encoding). The audit established type 1 as isochronous on the OHCI path;
// bulk and interrupt use the same encoding and are validated on hardware by
// the Bluetooth claim test before any data transfer depends on them.
enum UsbEndpointType {
  kUsbEndpointIsoch = 1,
  kUsbEndpointBulk = 2,
  kUsbEndpointInterrupt = 3
};
LONG UsbTransportOpen(void* handle, int type, int address, int max_packet,
                      int interval, DWORD* endpoint);
LONG UsbTransportControl(void* handle, void* transfer);
// Interrupt/bulk transfer through the kernel async queue (ordinal 748), with
// the same ownership rules as control transfers.
LONG UsbTransportAsync(void* handle, void* transfer);
LONG UsbTransportIsoch(void* handle, void* transfer, WORD* lengths);
// Passive caller: run a bounded, nonblocking operation in the USB domain.
typedef void (*UsbDomainRoutine)(void*);
LONG UsbTransportRun(UsbDomainRoutine routine, void* context);
// USB-domain only: no blocking dispatch. Same ownership and stop checks.
LONG UsbTransportIsochInDomain(void* handle, void* transfer, WORD* lengths);
// Called by completion callbacks before publishing their copied results.
BOOL UsbTransportComplete(void* transfer);
// USB-domain only: required before reusing a drained debug session.
BOOL UsbTransportIdleInDomain();
