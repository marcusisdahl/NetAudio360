#include <assert.h>
#include <stdio.h>

#include "cleanup_lifecycle.h"

int main() {
  usb_transport::CleanupLifecycle cleanup;
  assert(!cleanup.Complete(0));
  assert(!cleanup.Complete(~0u));
  assert(cleanup.Begin(3));
  assert(!cleanup.Begin(1));
  assert(cleanup.pending() == 3 && !cleanup.Ready(0));
  assert(cleanup.Complete(2));
  assert(cleanup.Complete(0));
  assert(!cleanup.Complete(0));
  assert(!cleanup.Complete(3));
  assert(cleanup.pending() == 1 && !cleanup.Finalize(0));
  assert(cleanup.Complete(1));
  assert(!cleanup.Ready(1));  // A transfer cancellation is still outstanding.
  assert(!cleanup.Finalize(1));
  assert(cleanup.Ready(0) && cleanup.Finalize(0));
  assert(!cleanup.Finalize(0));  // Removal completion is exactly once.
  assert(cleanup.finalized() && cleanup.Rearm());
  assert(!cleanup.begun() && !cleanup.Rearm());

  assert(cleanup.Begin(0));  // Setup failure before any endpoint opened.
  assert(cleanup.Ready(0) && cleanup.Finalize(0) && cleanup.Rearm());
  // Bluetooth: three data endpoints plus the default endpoint.
  assert(cleanup.Begin(4) && cleanup.pending() == 4);
  assert(cleanup.Complete(3) && cleanup.Complete(0) && cleanup.Complete(1));
  assert(!cleanup.Ready(0) && cleanup.Complete(2) && !cleanup.Complete(4));
  assert(cleanup.Finalize(0) && cleanup.Rearm());
  assert(!cleanup.Begin(5));
  puts("Asynchronous cleanup lifecycle tests passed");
  return 0;
}
