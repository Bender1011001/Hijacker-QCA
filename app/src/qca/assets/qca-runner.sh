#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Root supervisor. Capture is bounded even if the Android process disappears.
set -eu
export PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:$PATH
ACTION=${1:-probe}
SID=${2:-invalid}
OUT=${3:-invalid}
OWNER=${4:-0}
BSSID=${5:-all}
BASE=/data/local/tmp/hijacker-qca
KALI=/data/local/nhsystem/kali-arm64
PARAM=/sys/module/qca_cld3_peach_v2/parameters/con_mode
FWPARAM=/sys/module/firmware_class/parameters/path
STATE=$BASE/recovery
JOB=$KALI/tmp/hijacker-qca/$SID
SOURCE=${0%/*}
CPID=''
LOCKED=0
TOUCHED=0
CAPTURED=0

fail() { echo "ERROR:$*"; exit 1; }
phase() { echo "PHASE:$*"; }
case "$ACTION" in probe|capture|lab|restore) ;; *) fail 'Unknown operation';; esac
case "$SID" in ''|*[!a-zA-Z0-9_-]*) fail 'Invalid session';; esac
case "$OWNER" in ''|*[!0-9]*) fail 'Invalid owner PID';; esac
case "$OUT" in /data/user/0/dev.sir.hijackerqca/files/qca-sessions/"$SID"|/data/data/dev.sir.hijackerqca/files/qca-sessions/"$SID") ;; *) fail 'Invalid app output directory';; esac
[ "$(id -u)" = 0 ] || fail 'Root access was not granted'
[ -d "$OUT" ] || fail 'Missing app session directory'
[ -f "$PARAM" ] || fail 'qca_cld3_peach_v2 is not installed'
mkdir -p "$BASE"
chmod 700 "$BASE"

restore_radio() {
    [ -f "$STATE/pending" ] || return 0
    phase 'Restoring normal Wi-Fi'
    ip link set wlan0 down 2>/dev/null || true
    printf '0\n' > "$PARAM" || return 1
    sleep 3
    printf '%s\n' "$(cat "$STATE/firmware")" > "$FWPARAM" || return 1
    if [ "$(cat "$STATE/wifi")" = 1 ]; then svc wifi enable || return 1
    else svc wifi disable || return 1; fi
    # Restoring the setting is separate from reconnecting to an access point.
    TRIES=0
    while [ "$TRIES" -lt 10 ]; do
        [ "$(settings get global wifi_on)" = "$(cat "$STATE/wifi")" ] && break
        sleep 1
        TRIES=$((TRIES + 1))
    done
    [ "$(cat "$PARAM")" = 0 ] || return 1
    [ "$(cat "$FWPARAM")" = "$(cat "$STATE/firmware")" ] || return 1
    [ "$(settings get global wifi_on)" = "$(cat "$STATE/wifi")" ] || return 1
    # Do not clear the recovery marker while a radiotap interface remains.
    if [ -f /sys/class/net/wlan0/type ]; then
        [ "$(cat /sys/class/net/wlan0/type)" != 803 ] || return 1
    fi
    rm -f "$STATE/pending"
    TOUCHED=0
    phase 'Managed mode, firmware path and Wi-Fi setting restored; association is separate'
}

stop_child() {
    [ -n "$CPID" ] || return 0
    kill -INT "$CPID" 2>/dev/null || true
    sleep 1
    if kill -0 "$CPID" 2>/dev/null; then
        kill -TERM "$CPID" 2>/dev/null || true
        sleep 1
        kill -KILL "$CPID" 2>/dev/null || true
    fi
    wait "$CPID" 2>/dev/null || true
    CPID=''
    rm -f "$BASE/lock/child"
}

copy_results() {
    # These destinations are pre-created by the app: retain its UID and SELinux label.
    for NAME in result.json attempt.json device.json; do
        if [ -f "$JOB/$NAME" ]; then cat "$JOB/$NAME" > "$OUT/$NAME" || return 1; fi
    done
    if [ -f "$JOB/capture-01.csv" ]; then cat "$JOB/capture-01.csv" > "$OUT/capture.csv" || return 1; fi
    if [ -f "$JOB/capture-01.cap" ]; then cat "$JOB/capture-01.cap" > "$OUT/capture.pcap" || return 1; fi
    if [ -f "$JOB/capture.log" ]; then cat "$JOB/capture.log" > "$OUT/capture.log" || return 1; fi
}

cleanup() {
    CODE=$?
    trap - EXIT HUP INT TERM
    stop_child
    if [ "$TOUCHED" = 1 ]; then
        restore_radio || { echo 'ERROR:Restore failed. Recovery state retained; use Restore Wi-Fi.'; CODE=1; }
    fi
    copy_results || CODE=1
    MANAGED=false; PENDING=false
    [ "$(cat "$PARAM" 2>/dev/null || true)" != 0 ] || MANAGED=true
    [ ! -f "$STATE/pending" ] || PENDING=true
    printf '{"action":"%s","exit_code":%s,"managed_mode":%s,"recovery_pending":%s}\n' \
        "$ACTION" "$CODE" "$MANAGED" "$PENDING" > "$OUT/radio-state.json" || CODE=1
    if [ "$LOCKED" = 1 ]; then
        rm -f "$BASE/lock/pid" "$BASE/lock/child"
        rmdir "$BASE/lock" 2>/dev/null || true
    fi
    echo "EXIT:$CODE"
    exit "$CODE"
}

if ! mkdir "$BASE/lock" 2>/dev/null; then
    OLD=$(cat "$BASE/lock/pid" 2>/dev/null || true)
    case "$OLD" in ''|*[!0-9]*) fail 'Incomplete radio lock; inspect /data/local/tmp/hijacker-qca/lock';; esac
    if kill -0 "$OLD" 2>/dev/null; then fail 'Another Hijacker radio operation is running'; fi
    # An orphan capture is identified by its unique output directory, never by process name.
    CHILD=$(cat "$BASE/lock/child" 2>/dev/null || true)
    case "$CHILD" in ''|*[!0-9]*) ;; *)
        if [ -r "/proc/$CHILD/cmdline" ]; then
            tr '\000' ' ' < "/proc/$CHILD/cmdline" | grep -q '/tmp/hijacker-qca/' || fail 'Stale child PID belongs to another process'
            kill -TERM "$CHILD" 2>/dev/null || true
            sleep 1
            if kill -0 "$CHILD" 2>/dev/null; then
                kill -KILL "$CHILD" 2>/dev/null || true
                sleep 1
                kill -0 "$CHILD" 2>/dev/null && fail 'Orphan capture did not stop; recovery record retained'
            fi
        fi;;
    esac
    rm -f "$BASE/lock/pid" "$BASE/lock/child"
    rmdir "$BASE/lock"
    mkdir "$BASE/lock"
fi
LOCKED=1
echo $$ > "$BASE/lock/pid"
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

cancelled() { [ ! -f "$OUT/cancel" ] && kill -0 "$OWNER" 2>/dev/null; }
check_cancel() { cancelled || { phase 'Cancelled'; exit 130; }; }

if [ "$ACTION" = restore ]; then
    TOUCHED=1
    restore_radio || fail 'Recovery failed; saved state retained'
    [ "$(cat "$PARAM")" = 0 ] || fail 'Unknown monitor state; no Hijacker recovery record'
    printf '{"ok":true,"managed_mode":true}\n' > "$OUT/result.json"
    exit 0
fi

[ ! -d /data/local/tmp/benderlab/lock ] || fail 'Bender Lab holds the radio; stop it first'
[ ! -f "$STATE/pending" ] || fail 'Unfinished session: use Restore Wi-Fi first'
[ "$(cat "$PARAM")" = 0 ] || fail 'Radio is not managed; restore the tool that changed it first'
[ "$(getprop ro.product.model)" = CPH2655 ] || fail 'This experimental profile is limited to CPH2655'
[ "$(getprop ro.build.display.id)" = 'CPH2655_16.0.8.301(EX01)' ] || fail 'This Android build has not been validated for this profile'
HASH=$(sha256sum /vendor_dlkm/lib/modules/qca_cld3_peach_v2.ko)
[ "${HASH%% *}" = d6bd3fac600aaeba858e83292df167bc410457c07e422047c1a181c31d24d3df ] || fail 'Driver hash differs from the tested module'
[ -x "$KALI/usr/bin/python3" ] || fail 'Start the NetHunter ARM64 chroot first'
[ -x "$KALI/usr/sbin/airodump-ng" ] || fail 'Install aircrack-ng in NetHunter'
mkdir -p "$JOB" "$KALI/tmp/hijacker-qca/bin"
chmod 700 "$KALI/tmp/hijacker-qca"
for NAME in qca-backend.py netlink.py nl80211-constants.json; do cp "$SOURCE/$NAME" "$KALI/tmp/hijacker-qca/bin/$NAME"; done
cat "$OUT/request.json" > "$JOB/request.json"
getprop ro.product.model > "$JOB/model.txt"
getprop ro.build.display.id > "$JOB/build.txt"
uname -r > "$JOB/kernel.txt"
cat "$FWPARAM" > "$JOB/firmware.txt"
chroot "$KALI" /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    /usr/bin/python3 /tmp/hijacker-qca/bin/qca-backend.py probe "/tmp/hijacker-qca/$SID"
check_cancel
[ "$ACTION" != probe ] || exit 0

if [ "$ACTION" = capture ]; then
    if command -v droidspaces >/dev/null 2>&1; then
        droidspaces show | grep -qi 'No containers running' || fail 'Stop Droidspaces containers first'
    fi
    phase 'Preparing internal radio on channel 6'
    mkdir -p "$BASE/firmware/peach"
    # Refresh from this installed build, not a downloaded firmware image.
    cp -a /vendor/firmware_mnt/image/peach/. "$BASE/firmware/peach/"
    cp -a /odm/etc/wifi/peach/. "$BASE/firmware/peach/"
    chcon -R u:object_r:firmware_file:s0 "$BASE/firmware"
    [ -f "$BASE/firmware/peach/amss20.bin" ] || fail 'Firmware staging failed'
    mkdir -p "$STATE"
    cat "$FWPARAM" > "$STATE/firmware"
    settings get global wifi_on > "$STATE/wifi"
    case "$(cat "$STATE/wifi")" in 0|1) ;; *) fail 'Unsupported Wi-Fi setting; radio was not changed';; esac
    touch "$STATE/pending"
    TOUCHED=1
    printf '%s\n' "$BASE/firmware" > "$FWPARAM"
    svc wifi disable
    sleep 3
    check_cancel
    ip link set wlan0 down 2>/dev/null || true
    printf '4\n' > "$PARAM"
    sleep 4
    check_cancel
    ip link set wlan0 up
    iw dev wlan0 set channel 6
    [ "$(cat /sys/class/net/wlan0/type)" = 803 ] || fail 'Radiotap interface was not created'
    # BSSID was validated by Python before any radio changes.
    if [ "$BSSID" = all ]; then set --; else set -- --bssid "$BSSID"; fi
    chroot "$KALI" /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC TERM=xterm \
        /usr/sbin/airodump-ng --background 1 --channel 6 --write-interval 1 \
        --output-format pcap,csv --write "/tmp/hijacker-qca/$SID/capture" "$@" wlan0 > "$JOB/capture.log" 2>&1 &
    CPID=$!
    echo "$CPID" > "$BASE/lock/child"
    echo 'READY:Radiotap RX; channel 6; maximum 60 seconds'
    N=0
    while [ "$N" -lt 60 ]; do
        kill -0 "$CPID" 2>/dev/null || fail 'airodump exited unexpectedly; see capture.log'
        check_cancel
        sleep 1
        N=$((N + 1))
        if [ $((N % 2)) = 0 ] && [ -s "$JOB/capture-01.csv" ]; then
            echo 'CSV_BEGIN'
            # Network names are untrusted text: encode them so they cannot spoof control lines.
            base64 "$JOB/capture-01.csv"
            echo 'CSV_END'
        fi
    done
    stop_child
    restore_radio || fail 'Restore failed; recovery record retained'
    chroot "$KALI" /usr/bin/env TZ=UTC /usr/bin/python3 /tmp/hijacker-qca/bin/qca-backend.py capture "/tmp/hijacker-qca/$SID"
else
    check_cancel
    phase 'Validating the selected client and managed interface'
    # One request, no retry: the Python process records intent before transmission.
    chroot "$KALI" /usr/bin/env TZ=UTC /usr/bin/python3 /tmp/hijacker-qca/bin/qca-backend.py lab "/tmp/hijacker-qca/$SID"
fi
