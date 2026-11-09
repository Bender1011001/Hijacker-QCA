# Validation record

November 9, 2026 · `1.5-qca.1` · `dev.sir.hijackerqca`

**Host-built prototype; handset validation pending.** The phone was disconnected during the port and its owner requested continued building. No radio transmission was performed by these host tests.

| Check | Result / scope |
|---|---|
| Debug APK build | Passed: JDK 17 / Gradle 8.10.2 / AGP 8.7.3 / SDK 35 |
| Five Java parser tests | Passed: SSID commas/spaces, UTF-8 lengths, association, incomplete rows, hidden SSID |
| Seven Python backend tests | Passed: authorization, freshness/association, channel/path checks, one submission, cooldown, timeout, missing/mismatched ACK |
| Five supervisor tests | Passed: mocked completion/export, transition cancellation, start failure, failed restore with later recovery, unsupported-profile refusal |
| Android lint | Passed with zero errors and 278 warnings; legacy, deprecation, styling and localization warnings remain |
| APK inspection | Signature verified; application ID and API 30/35 bounds match; five packaged assets match source; no native libraries or legacy executable assets |
| Install/launch/root prompt | Pending on OnePlus 13 |
| Live AP/client rows and exported pcap/CSV | Pending in this app |
| Stop, background handling, app closure and restoration | Pending on Android; host mocks do not validate firmware timing or SELinux |
| Single-frame result and independently observed effect | Pending in this app; no PMF-bypass claim |

The local debug APK is 14,837,730 bytes, SHA-256 `bb1f93d52cf5164870ea8019d0227930cc5496a73416731fba358715a1d54c20`. This identifies the inspected build, not an on-phone test. Local logs are retained in the ignored `validation/` directory; exported build metadata pairs the APK with its source commit.

## Required handset acceptance

Record APK SHA-256, source commit, exact build/module and NetHunter tool versions. Preserve raw session exports privately; publish only reviewed redactions.

1. Install beside original Hijacker, grant root and run read-only preflight. Verify launch does not switch radio mode.
2. Capture on channel 6; compare live AP/client rows with CSV and independently parse the exported pcap.
3. Cancel one capture, then complete a bounded one. Verify mode 0, saved loader path and Wi-Fi setting after both; separately verify AP association.
4. Exercise notification Stop, background handling, interrupted-session recovery and **Restore Wi-Fi**. Preserve at least one failure/cancellation export.
5. Only against selected authorized lab hardware, perform a single-frame test after capture/restoration. Retain cookie/ACK and independently observe the AP/client. A successful request is not a demonstrated disconnect.

A public APK release and a demonstration of working Hijacker support should wait for these checks. Underlying radio research must remain distinguished from application-level validation.
