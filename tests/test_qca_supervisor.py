"""Run the actual supervisor control flow in a temporary mocked filesystem.

No root, chroot, Android settings, real process-group signals or radio operations.
Absolute device paths in a disposable script copy point only inside TemporaryDirectory.
The mocks model control flow, not firmware timing or SELinux on Android.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ASSETS = Path(__file__).resolve().parents[1] / 'app/src/qca/assets'
GIT_BASH = Path('C:/Program Files/Git/bin/bash.exe')
BASH = str(GIT_BASH) if os.name == 'nt' and GIT_BASH.exists() else shutil.which('bash')


def shell_path(path):
    text = Path(path).resolve().as_posix()
    return '/' + text[0].lower() + text[2:] if os.name == 'nt' else text


MOCKS = r'''
id() { echo 0; }
getprop() {
    case "$1" in
        ro.product.model) echo "${MOCK_MODEL:-CPH2655}";;
        ro.build.display.id) echo 'CPH2655_16.0.8.301(EX01)';;
    esac
}
sha256sum() { echo 'd6bd3fac600aaeba858e83292df167bc410457c07e422047c1a181c31d24d3df  fixture'; }
settings() { cat "$MOCK_ROOT/wifi"; }
svc() {
    if [ "$2" = enable ]; then
        [ "${MOCK_RESTORE_FAIL:-0}" = 0 ] || return 1
        echo 1 > "$MOCK_ROOT/wifi"; echo 1 > "$MOCK_ROOT/type"
    else echo 0 > "$MOCK_ROOT/wifi"; fi
}
ip() {
    if [ "$4" = up ] && [ "$(cat "$PARAM")" = 4 ]; then
        [ "${MOCK_START_FAIL:-0}" = 0 ] || return 1
        echo 803 > "$MOCK_ROOT/type"
    fi
}
iw() { :; }
chcon() { :; }
sleep() {
    if [ "${MOCK_CANCEL:-0}" = 1 ] && [ "$(cat "$PARAM")" = 4 ]; then touch "$OUT/cancel"; fi
    command sleep 0.01
}
kill() {
    if [ "$1" = -0 ] && [ "$2" = 999999 ]; then return 0; fi
    builtin kill "$@"
}
chroot() {
    case "$*" in
        *'/usr/sbin/airodump-ng '*)
            printf 'BSSID, header\n02:11:22:33:44:50, fixture\n' > "$JOB/capture-01.csv"
            printf 'mock pcap data' > "$JOB/capture-01.cap"
            # exec means the supervisor owns this exact process, not a grandchild.
            exec sleep 30;;
        *' probe '*) printf '{"ok":true,"action":"probe"}\n' > "$JOB/result.json";;
        *' capture '*) printf '{"ok":true,"action":"capture"}\n' > "$JOB/result.json";;
        *) echo 'Unexpected mocked chroot action' >&2; return 1;;
    esac
}
'''


@unittest.skipUnless(BASH, 'bash is required for shell control-flow tests')
class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hijacker-supervisor-')
        self.root = Path(self.tmp.name)
        self.posix = shell_path(self.root)
        for path in ('app/s1', 'vendor', 'odm', 'kali/usr/bin', 'kali/usr/sbin'):
            (self.root / path).mkdir(parents=True)
        for name, value in [('mode', '0\n'), ('firmware', '\n'), ('wifi', '1\n'), ('type', '1\n'),
                            ('vendor/amss20.bin', 'mock'), ('app/s1/request.json', '{"channel":6}')]:
            (self.root / name).write_text(value)
        for name in ('python3', '../sbin/airodump-ng'):
            executable = self.root / 'kali/usr/bin' / name
            executable.write_text('#!/bin/sh\nexit 99\n'); executable.chmod(0o700)
        for name in ('qca-backend.py', 'netlink.py', 'nl80211-constants.json'):
            (self.root / name).write_text('mock helper; never executed')
        script = (ASSETS / 'qca-runner.sh').read_text()
        substitutions = {
            '/data/local/tmp/hijacker-qca': self.posix + '/state',
            '/data/local/nhsystem/kali-arm64': self.posix + '/kali',
            '/sys/module/qca_cld3_peach_v2/parameters/con_mode': self.posix + '/mode',
            '/sys/module/firmware_class/parameters/path': self.posix + '/firmware',
            '/sys/class/net/wlan0/type': self.posix + '/type',
            '/data/user/0/dev.sir.hijackerqca/files/qca-sessions': self.posix + '/app',
            '/data/local/tmp/benderlab/lock': self.posix + '/other-lock',
            '/vendor/firmware_mnt/image/peach': self.posix + '/vendor',
            '/odm/etc/wifi/peach': self.posix + '/odm',
        }
        for before, after in substitutions.items(): script = script.replace(before, after)
        self.script = self.root / 'runner.sh'
        self.script.write_text('#!/bin/bash\n' + MOCKS + script.partition('\n')[2], newline='\n')

    def tearDown(self):
        self.tmp.cleanup()

    def run_supervisor(self, action='capture', **overrides):
        env = {**os.environ, 'MOCK_ROOT': self.posix, **overrides}
        result = subprocess.run([BASH, shell_path(self.script), action, 's1', self.posix + '/app/s1', '999999', 'all'],
                                env=env, capture_output=True, text=True, timeout=25)
        self.output = result.stdout + result.stderr
        return result.returncode

    def assert_restored(self):
        self.assertEqual('0', (self.root / 'mode').read_text().strip(), self.output)
        self.assertEqual('\n', (self.root / 'firmware').read_text(), self.output)
        self.assertEqual('1', (self.root / 'wifi').read_text().strip(), self.output)
        self.assertFalse((self.root / 'state/recovery/pending').exists(), self.output)
        self.assertFalse((self.root / 'state/lock').exists(), self.output)

    def test_completed_capture_restores_and_exports(self):
        self.assertEqual(0, self.run_supervisor(), self.output)
        self.assert_restored()
        self.assertTrue((self.root / 'app/s1/capture.pcap').exists(), self.output)
        state = json.loads((self.root / 'app/s1/radio-state.json').read_text())
        self.assertTrue(state['managed_mode']); self.assertFalse(state['recovery_pending'])
        self.assertIn('CSV_BEGIN', self.output)

    def test_cancel_during_transition_restores(self):
        self.assertEqual(130, self.run_supervisor(MOCK_CANCEL='1'), self.output)
        self.assert_restored()

    def test_capture_start_failure_restores(self):
        self.assertEqual(1, self.run_supervisor(MOCK_START_FAIL='1'), self.output)
        self.assertIn('Restoring normal Wi-Fi', self.output)
        self.assert_restored()

    def test_failed_restore_keeps_record_then_manual_recovery_succeeds(self):
        self.assertEqual(1, self.run_supervisor(MOCK_CANCEL='1', MOCK_RESTORE_FAIL='1'), self.output)
        self.assertTrue((self.root / 'state/recovery/pending').exists(), self.output)
        # Recovery must remain available even if the normal profile check would fail.
        self.assertEqual(0, self.run_supervisor('restore', MOCK_MODEL='different-build'), self.output)
        self.assert_restored()

    def test_unvalidated_device_fails_before_radio_change(self):
        self.assertEqual(1, self.run_supervisor(MOCK_MODEL='different-device'), self.output)
        self.assert_restored()
        self.assertIn('limited to CPH2655', self.output)


if __name__ == '__main__':
    unittest.main()
