# Internal QCA backend

Base: Hijacker `898af5b530dd000b8251f21da94626d9e41e53d2`. The fork uses a distinct application ID, SDK 35, JDK 17, and current-for-this-build Android dependencies. Legacy JNI parsing and ARMv7 binaries are not packaged. Existing UI/model source is retained where practical; unsupported controls are blocked.

## Receive

`Airodump.start()` delegates to `QcaBackend`. One worker serializes operations, creates a private session, starts `QcaRadioService` and invokes `qca-runner.sh` through root. The supervisor verifies the profile/chroot and managed interface. It stages the installed firmware unchanged, saves the loader path and Wi-Fi setting, creates a persistent recovery record, disables Wi-Fi and sets `con_mode=4`. This recreates the netdev; it is not the generic `iw interface add` mechanism.

After verifying type 803 and channel 6, the supervisor runs ARM64 `airodump-ng` with `--background 1`, fixed channel, UTF-8 locale, UTC timezone and pcap/CSV output. There are at most 60 one-second capture-loop iterations, plus transition and cleanup overhead. The exact child PID is owned by the supervisor. CSV snapshots cross the root pipe as base64, so network names cannot impersonate control lines. `QcaCsv` tolerates partial rows and updates AP/ST models on Android's main thread.

Cleanup stops the child, restores mode 0, writes the saved loader path (including a newline for an empty value), and restores the Wi-Fi setting. It checks these values and that an existing `wlan0` is no longer radiotap before clearing the recovery record. Reassociation is a separate observation. Copies into app-precreated files preserve the app UID and SELinux labels.

## Managed management-frame operation

A separate client action is available only while no other operation is running. The backend re-reads the captured AP/client association and UTC timestamps, checks channel-6 beacons and client traffic, explicit authorization, distinct unicast addresses, and a 120-second freshness limit. It obtains the current interface index after mode changes and checks `NL80211_EXT_FEATURE_AUTH_AND_DEAUTH_RANDOM_TA`.

After recording intent, Python submits one `NL80211_CMD_FRAME` request through managed `wlan0` at 2437 MHz. It records the returned cookie and TX-status event. An ACK counts as matching only when cookie, interface index and exact frame bytes match. No automatic retry occurs, including on timeout. There is no aireplay shim or manufactured injection-success output.

## Lifecycle

- An Android foreground service uses the `connectedDevice` type, required permissions and a visible Stop action.
- One worker and one root lock prevent overlap within this fork. A Bender Lab lock also blocks capture; operators must stop other radio tools themselves.
- The root loop polls the app PID and cancellation file. Handled signals, capture exit, cancellation and transition failures invoke cleanup. A 150-second app deadline requests cancellation and terminates its root process handle.
- Failed restoration retains the record and blocks normal operations. **Restore Wi-Fi** bypasses the ordinary profile/chroot preflight so saved state can be recovered after a profile change.
- Stale-lock recovery waits for the owner to be gone and verifies an orphan child's private session path before terminating its PID.
- Host tests do not model firmware timing, SELinux, Android process management, SIGKILL, reboot or kernel failure. No automatic boot recovery is installed.

## Evidence

Sessions contain `request.json`, `completion.json`, `supervisor.log`, and, when root cleanup is reached, `radio-state.json`. Python supplies `device.json` and `result.json`. Lab actions also write `attempt.json`; captures include pcap, CSV and a tool log. The ZIP exporter grants access only to the export directory, not all external storage.

Read completion/restore state alongside the Python result: a cancelled capture may retain a successful preliminary `probe` result. An intent marker is not proof of transmission. Kernel acceptance, driver ACK, RF observation and independently observed target behavior are separate evidence levels. The app does not measure target disconnection.

Private session data stays local until the user chooses a sharing destination. No private AP/client profile is embedded in source; tests use synthetic identifiers.
