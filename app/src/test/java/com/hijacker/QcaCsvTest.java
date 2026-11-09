package com.hijacker;

import org.junit.Test;
import static org.junit.Assert.*;

public class QcaCsvTest {
    private static String ap(String ssid, int length) {
        return "02:11:22:33:44:50, 2026-11-09 12:00:00, 2026-11-09 12:00:01, 6, 54, WPA2, CCMP, PSK, -42, 20, 3, 0. 0. 0. 0, " + length + ", " + ssid + ", \n";
    }
    @Test public void retainsSsidCommasAndSpaces() {
        QcaCsv result = QcaCsv.parse("BSSID, header\n" + ap("Lab, room", 9));
        assertEquals(1, result.aps.size()); assertEquals("Lab, room", result.aps.get(0).ssid);
        assertEquals(6, result.aps.get(0).channel); assertEquals(20, result.aps.get(0).beacons);
    }
    @Test public void utf8SsidUsesByteLength() {
        assertEquals("Caf\u00e9", QcaCsv.parse(ap("Caf\u00e9", 5)).aps.get(0).ssid);
    }
    @Test public void associatesStationAndKeepsUnknownStation() {
        QcaCsv result = QcaCsv.parse(ap("Lab", 3) + "Station MAC, header\n"
            + "02:11:22:33:44:60, t, t, -51, 7, 02:11:22:33:44:50, Lab\n"
            + "02:11:22:33:44:62, t, t, -80, 2, (not associated), One, Two\n");
        assertEquals(2, result.stations.size()); assertEquals(7, result.stations.get(0).frames);
        assertEquals("02:11:22:33:44:50", result.stations.get(0).bssid);
        assertNull(result.stations.get(1).bssid); assertEquals("One, Two", result.stations.get(1).probes);
    }
    @Test public void partialRewriteDoesNotCrashOrDiscardValidRows() {
        QcaCsv result = QcaCsv.parse(ap("Lab", 3) + "02:11:22:33:44:52, partial\n" + ap("Other", 5).replace("-42", "bad"));
        assertEquals(1, result.aps.size()); assertEquals(2, result.rejected);
    }
    @Test public void hiddenSsidIsNull() { assertNull(QcaCsv.parse(ap("", 0)).aps.get(0).ssid); }
}
