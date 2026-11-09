#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Small generic-netlink transport with bounded nl80211 replies and TX status waits."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import struct
import time

C = json.loads(Path(__file__).with_name('nl80211-constants.json').read_text())

def u32(n):
    return struct.pack('=I', n)

def attr(kind, data):
    n = len(data) + 4
    return struct.pack('=HH', n, kind) + data + b'\x00' * (-n % 4)

def attrs(data):
    out = {}
    while len(data) >= 4:
        n, kind = struct.unpack_from('=HH', data)
        if n < 4 or n > len(data):
            raise ValueError('Malformed netlink attribute')
        out[kind & 0x3fff] = data[4:n]
        data = data[(n + 3) & ~3:]
    return out

def a(name, data):
    return attr(C['NL80211_ATTR_' + name], data)

def number(data):
    return int.from_bytes(data, 'little')

class Netlink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        self.sock.bind((0, 0))
        self.sock.settimeout(0.3)
        self.seq = 0
        self.events = []
        replies = self.request(16, 3, attr(2, b'nl80211\x00'))
        family = attrs(replies[0][1][4:])
        self.family = number(family[1])
        self.groups = {}
        for group in attrs(family.get(7, b'')).values():
            fields = attrs(group)
            name = fields[1].rstrip(b'\x00').decode()
            self.groups[name] = number(fields[2])
        self.sock.setsockopt(270, 1, u32(self.groups['mlme']))

    def receive(self):
        data = self.sock.recv(262144)
        messages = []
        while len(data) >= 16:
            length, kind, flags, seq, pid = struct.unpack_from('=IHHII', data)
            if length < 16 or length > len(data):
                raise ValueError('Malformed netlink message')
            messages.append((kind, data[16:length], seq))
            data = data[(length + 3) & ~3:]
        return messages

    def request(self, family, command, data, dump=False):
        self.seq += 1
        payload = struct.pack('=BBH', command, 1, 0) + data
        flags = 0x301 if dump else 5
        header = struct.pack('=IHHII', len(payload) + 16, family, flags,
                             self.seq, self.sock.getsockname()[0])
        self.sock.sendto(header + payload, (0, 0))
        replies = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                batch = self.receive()
            except socket.timeout:
                continue
            finished = False
            for kind, body, seq in batch:
                if seq != self.seq:
                    self.events.append((kind, body, seq))
                elif kind == 2:
                    error = struct.unpack_from('=i', body)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    finished = True
                elif kind == 3:
                    error = struct.unpack_from('=i', body)[0] if len(body) >= 4 else 0
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    finished = True
                else:
                    replies.append((kind, body, seq))
            if finished:
                return replies
        raise TimeoutError('No completed netlink reply')

    def command(self, name, data, dump=False):
        return self.request(self.family, C['NL80211_CMD_' + name], data, dump)

    def tx_status(self, cookie, seconds=6):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            batch, self.events = self.events, []
            if not batch:
                try:
                    batch = self.receive()
                except socket.timeout:
                    continue
            for kind, body, seq in batch:
                if kind != self.family or not body or body[0] != C['NL80211_CMD_FRAME_TX_STATUS']:
                    continue
                fields = attrs(body[4:])
                if number(fields.get(C['NL80211_ATTR_COOKIE'], b'')) != cookie:
                    continue
                return {'cookie': cookie, 'ack': C['NL80211_ATTR_ACK'] in fields,
                        'frame_hex': fields.get(C['NL80211_ATTR_FRAME'], b'').hex(),
                        'ifindex': number(fields.get(C['NL80211_ATTR_IFINDEX'], b''))}
        return None
