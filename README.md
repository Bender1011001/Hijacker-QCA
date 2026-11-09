# Hijacker QCA Lab

An experimental fork of [Hijacker](https://github.com/chrisk44/Hijacker/tree/898af5b530dd000b8251f21da94626d9e41e53d2) for the **OnePlus 13 internal Wi-Fi radio**.

**Host-built prototype: this Hijacker APK has not yet been validated on a phone.** The underlying radio paths were demonstrated separately in [the research repository](https://github.com/Bender1011001/oneplus13-internal-wifi-research). Those results do not establish application-level success. See [VALIDATION.md](VALIDATION.md).

| Feature | Mechanism | Current limit |
|---|---|---|
| Passive AP/client display and capture | QCA `con_mode=4` recreates `wlan0` as a radiotap netdev; NetHunter ARM64 `airodump-ng` produces CSV/pcap | Channel 6, up to 60 seconds |
| Selected-client lab action | Root `NL80211_CMD_FRAME` on managed `wlan0`, after capture stops and mode 0 is restored | One directed deauthentication request; no automatic retry |
| Recovery and export | Foreground service, root supervisor, persistent recovery record, session ZIP | Host-tested control flow; Android behavior pending |

This does **not** add general monitor-mode TX, aireplay injection, channel hopping, Reaver, MDK, simultaneous RX/TX, or a PMF bypass. Unsupported tool controls are hidden or blocked. The independent [negative aireplay test](https://github.com/Bender1011001/oneplus13-internal-wifi-research/blob/main/docs/AIREPLAY_TEST.md) remains valid.

## Required profile

The supervisor checks model, build and module hash before a normal operation:

- OnePlus **CPH2655**, Android 16 build **CPH2655_16.0.8.301(EX01)**.
- Underlying tested kernel: `6.6.89-android15-8-g97a9aaefab9a-ab14519050-4k`.
- `/vendor_dlkm/lib/modules/qca_cld3_peach_v2.ko`, SHA-256 `d6bd3fac600aaeba858e83292df167bc410457c07e422047c1a181c31d24d3df`.
- Root through `su`. The underlying experiment used Magisk; KernelSU is untested with this fork.
- Running ARM64 NetHunter chroot at `/data/local/nhsystem/kali-arm64`, working proc/sys/dev mounts, Python 3 and `/usr/sbin/airodump-ng`. The tool-level test used aircrack-ng 1.7.
- Android `iw`, `ip`, `svc`, `settings`, `chroot`, `base64`, `sha256sum` and the installed vendor/ODM firmware files.

Firmware is copied unchanged from the installed build into a temporary loader directory. No downloaded firmware, replacement driver, flashing operation, Nexmon preload, external adapter or legacy ARMv7 executable is packaged. Root is required for radio/netlink operations, not merely for CSV parsing. A Snapdragon 8 Elite or GKI 6.6 label alone does not establish compatibility.

## Build

Use JDK 17 and Android SDK Platform 35; configure `sdk.dir` in ignored `local.properties` or set `ANDROID_HOME`. The wrapper uses Gradle 8.10.2 and AGP 8.7.3.

```sh
./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
python -m unittest discover -s tests -v
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On Windows use `gradlew.bat`. Host tests require Python 3.10+ and Bash (Git for Windows Bash on Windows). They mock device interfaces and never transmit frames.

Application: **Hijacker QCA Lab**, `dev.sir.hijackerqca`, version `1.5-qca.1`. It installs alongside original Hijacker. A debug build uses your local Android debug key; a differently signed build may require uninstalling the previous one. Export wanted sessions before uninstalling.

## Intended handset workflow

1. Start NetHunter, keep normal Wi-Fi enabled, open the app and grant root. Opening the app does not start capture.
2. Choose **Check radio and NetHunter** and inspect the result.
3. Press **Start**, or select a channel-6 AP for capture. Normal Wi-Fi disconnects during capture. AP/client rows should update from the CSV.
4. Press **Stop** or wait for the 60-second limit. Check the final state. Restoring the Wi-Fi setting does not itself prove reassociation with an AP.
5. Optionally select a client and choose **Single-frame lab test**. The backend requires explicit authorization, a channel-6 AP/client association observed within 120 seconds, beacons and client traffic, distinct unicast addresses, managed mode and the required advertised feature. Attempts are separated by at least 30 seconds.
6. Inspect **Latest result / log** and **Export latest session**. Exports contain private MAC addresses and raw packets; review/redact before publishing. The user chooses the Android sharing destination.

Only transmit management frames against hardware you own or are explicitly authorized to test. Choose a noncritical lab client: this can interrupt wireless service. One userspace submission can produce hardware retries. Driver acceptance and a matching ACK are distinct from observed disconnection and do not establish a PMF bypass. A timeout after intent is recorded has an uncertain outcome; it is never automatically retried.

## Recovery

Use **Restore Wi-Fi** after an interrupted session. Saved state is under `/data/local/tmp/hijacker-qca/recovery/`: `pending`, `firmware` and `wifi`. Do not delete the record to bypass recovery or replace the saved loader path with a guess. An empty loader path is restored by writing a newline. Recovery remains available even if normal model/build/chroot checks fail.

Inspect `radio-state.json`, `completion.json` and the supervisor log. A hard-killed supervisor, kernel failure or Android/SELinux issue may require manual investigation. There is no boot persistence. Root-side stale-child recovery checks the process command line before terminating a PID; no tool-name-wide killing is used.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for lifecycle and evidence details.

## Credits and license

Upstream Hijacker is copyright Christos Kyriakopoulos and contributors. This derivative and its new backend are **GPL-3.0-or-later**; see [COPYING](COPYING). The OUI database comes from upstream. Research and port work: [Bender1011001](https://github.com/Bender1011001). Original notices/history and [upstream README](UPSTREAM_README.md) are retained; its feature claims describe the original app, not this fork. This is an independent experimental project, not an official Hijacker or Kali release.
