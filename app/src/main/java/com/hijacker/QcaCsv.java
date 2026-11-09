/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.hijacker;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Parse complete rows from airodump's periodically rewritten CSV. No Android dependency. */
final class QcaCsv {
    static final class AccessPoint {
        String mac, ssid, privacy, cipher, auth;
        int channel, power, beacons, data;
    }
    static final class Station {
        String mac, bssid, probes;
        int power, frames;
    }
    final List<AccessPoint> aps = new ArrayList<>();
    final List<Station> stations = new ArrayList<>();
    int rejected;

    static boolean isMac(String value) { return value.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}"); }
    static String address(String value) { return value.trim().toUpperCase(Locale.ROOT); }

    static QcaCsv parse(String text) {
        QcaCsv result = new QcaCsv();
        boolean stationSection = false;
        for (String line : text.split("\\r?\\n")) {
            if (line.trim().isEmpty() || line.startsWith("BSSID")) continue;
            if (line.startsWith("Station MAC")) { stationSection = true; continue; }
            String[] f = line.split(",", -1);
            if (f.length == 0 || !isMac(f[0].trim())) { result.rejected++; continue; }
            try {
                if (!stationSection && f.length >= 15) {
                    AccessPoint ap = new AccessPoint();
                    ap.mac = address(f[0]); ap.channel = Integer.parseInt(f[3].trim());
                    ap.privacy = f[5].trim(); ap.cipher = f[6].trim(); ap.auth = f[7].trim();
                    ap.power = Integer.parseInt(f[8].trim()); ap.beacons = Integer.parseInt(f[9].trim());
                    ap.data = Integer.parseInt(f[10].trim());
                    int length = Integer.parseInt(f[12].trim());
                    String tail = line.split(",", 14)[13];
                    if (tail.startsWith(" ")) tail = tail.substring(1);
                    byte[] bytes = tail.getBytes(StandardCharsets.UTF_8);
                    if (length < 0 || length > 32 || bytes.length < length) throw new IllegalArgumentException("SSID length");
                    ap.ssid = length == 0 ? null : new String(Arrays.copyOf(bytes, length), StandardCharsets.UTF_8);
                    result.aps.add(ap);
                } else if (stationSection && f.length >= 6) {
                    Station st = new Station();
                    st.mac = address(f[0]); st.power = Integer.parseInt(f[3].trim());
                    st.frames = Integer.parseInt(f[4].trim());
                    st.bssid = isMac(f[5].trim()) ? address(f[5]) : null;
                    st.probes = f.length > 6 ? String.join(",", Arrays.copyOfRange(f, 6, f.length)).trim() : "";
                    result.stations.add(st);
                } else result.rejected++;
            } catch (IllegalArgumentException error) { result.rejected++; }
        }
        return result;
    }
}
