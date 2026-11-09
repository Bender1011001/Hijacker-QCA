"""Host-only tests. Never open a netlink socket or transmit a frame."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ASSETS = Path(__file__).resolve().parents[1] / 'app/src/qca/assets'
sys.path.insert(0, str(ASSETS))
SPEC = importlib.util.spec_from_file_location('backend', ASSETS / 'qca-backend.py')
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
AP = '02:11:22:33:44:50'
CLIENT = '02:11:22:33:44:60'
EPOCH = 1794225601.0  # 2026-11-09T12:00:01Z


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.capture = self.base / 'capture_1'
        self.capture.mkdir()
        self.csv = self.capture / 'capture-01.csv'
        self.csv.write_text(f'BSSID, header\n{AP}, 2026-11-09 12:00:00, 2026-11-09 12:00:01, 6, 54, WPA2, CCMP, PSK, -40, 5, 3, 0, 3, Lab, \n\nStation MAC, header\n{CLIENT}, 2026-11-09 12:00:00, 2026-11-09 12:00:01, -51, 5, {AP}, \n')
        self.request = dict(channel=6, ap=AP, client=CLIENT, capture_session='capture_1', authorized_owned_hardware=True)
        self.job = self.base / 'lab_1'
        self.job.mkdir()
        (self.job / 'device.json').write_text(json.dumps({'auth_deauth_random_ta': True}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_recent_selection(self):
        self.assertEqual((AP, CLIENT), B.validate_target(self.request, self.csv, EPOCH))

    def test_stale_future_and_wrong_client_rejected(self):
        for now in [EPOCH + 121, EPOCH - 10]:
            with self.assertRaises(ValueError): B.validate_target(self.request, self.csv, now)
        self.request['client'] = '02:11:22:33:44:62'
        with self.assertRaises(ValueError): B.validate_target(self.request, self.csv, EPOCH)

    def test_authorization_and_nonbroadcast_required(self):
        self.request['authorized_owned_hardware'] = False
        with self.assertRaises(ValueError): B.validate_target(self.request, self.csv, EPOCH)
        for value in ['ff:ff:ff:ff:ff:ff', '01:11:22:33:44:55', '00:00:00:00:00:00', 'x;touch /tmp/a']:
            with self.assertRaises(ValueError): B.mac(value)

    def test_wrong_channel_and_source_path_rejected_before_netlink(self):
        with patch.object(B, 'Netlink') as netlink:
            self.request['channel'] = 11
            with self.assertRaises(ValueError): B.single_frame(self.job, self.request)
            self.request['channel'] = 6; self.request['capture_session'] = '../escape'
            with self.assertRaises(ValueError): B.single_frame(self.job, self.request)
            netlink.assert_not_called()

    def test_single_submission_and_matching_status(self):
        nl = MagicMock()
        nl.command.return_value = [(1, b'\x00' * 4 + B.a('COOKIE', struct.pack('=Q', 256)), 1)]
        frame = struct.pack('<HH', 0xc0, 0) + bytes.fromhex(CLIENT.replace(':', '')) + bytes.fromhex(AP.replace(':', '')) * 2 + struct.pack('<HH', 0, 3)
        nl.tx_status.return_value = dict(cookie=256, ack=True, ifindex=47, frame_hex=frame.hex())
        with patch.object(B, 'BASE', self.base), patch.object(B.time, 'time', return_value=EPOCH), patch.object(B, 'interface', return_value=(47, {})), patch.object(B, 'Netlink', return_value=nl):
            result = B.single_frame(self.job, self.request)
            self.assertTrue(result['matching_ack'])
            nl.command.assert_called_once()
            self.assertEqual('FRAME', nl.command.call_args.args[0])
            self.assertTrue((self.job / 'attempt.json').exists())
            with self.assertRaises(RuntimeError): B.single_frame(self.job, self.request)
            self.assertEqual(1, nl.command.call_count)

    def test_timeout_records_intent_without_retry(self):
        nl = MagicMock(); nl.command.side_effect = TimeoutError('test')
        with patch.object(B, 'BASE', self.base), patch.object(B.time, 'time', return_value=EPOCH), patch.object(B, 'interface', return_value=(47, {})), patch.object(B, 'Netlink', return_value=nl):
            with self.assertRaises(TimeoutError): B.single_frame(self.job, self.request)
        self.assertEqual(1, nl.command.call_count)
        self.assertTrue((self.job / 'attempt.json').exists())
        nl.sock.close.assert_called_once()

    def test_missing_or_unrelated_ack_does_not_become_success_evidence(self):
        frame = struct.pack('<HH', 0xc0, 0) + bytes.fromhex(CLIENT.replace(':', '')) + bytes.fromhex(AP.replace(':', '')) * 2 + struct.pack('<HH', 0, 3)
        correct = dict(cookie=256, ack=True, ifindex=47, frame_hex=frame.hex())
        for status in [None, {**correct, 'cookie': 257}, {**correct, 'ifindex': 48},
                       {**correct, 'frame_hex': '00'}, {**correct, 'ack': False}]:
            with self.subTest(status=status):
                (self.base / 'last-attempt.json').unlink(missing_ok=True)
                nl = MagicMock()
                nl.command.return_value = [(1, b'\x00' * 4 + B.a('COOKIE', struct.pack('=Q', 256)), 1)]
                nl.tx_status.return_value = status
                with patch.object(B, 'BASE', self.base), patch.object(B.time, 'time', return_value=EPOCH), patch.object(B, 'interface', return_value=(47, {})), patch.object(B, 'Netlink', return_value=nl):
                    result = B.single_frame(self.job, self.request)
                self.assertTrue(result['kernel_accepted'])
                self.assertFalse(result['matching_ack'])
                nl.command.assert_called_once()


if __name__ == '__main__':
    unittest.main()
