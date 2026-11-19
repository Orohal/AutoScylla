#pragma once

// Start the loopback control server (127.0.0.1:27043) in a background thread.
// Returns true if the listener was created.
bool AutoScyllaServer_Start();

// Stop the server and close the listener.
void AutoScyllaServer_Stop();
