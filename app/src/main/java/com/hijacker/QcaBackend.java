/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.hijacker;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.view.Menu;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.FileProvider;
import org.json.JSONObject;
import java.io.*;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** One serialized QCA operation; the root supervisor owns radio restoration. */
final class QcaBackend {
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private static final ScheduledExecutorService TIMER = Executors.newSingleThreadScheduledExecutor();
    private static final int INFO = 9101, RESTORE = 9102, SHARE = 9103, PROBE = 9104;
    private static final String[] ASSETS = {"qca-runner.sh", "qca-backend.py", "netlink.py", "nl80211-constants.json"};
    private static final String[] OUTPUTS = {"capture.pcap", "capture.csv", "capture.log", "result.json", "attempt.json", "device.json", "radio-state.json"};
    private static Context context;
    private static WeakReference<MainActivity> activity = new WeakReference<>(null);
    private static File tools, sessions;
    private static volatile File current, latest, lastCapture;
    private static volatile boolean busy;
    private static volatile String action = "", phase = "Internal QCA · channel 6 · ready";

    static boolean enabled() { return true; }
    static boolean isCapturing() { return busy && action.equals("capture"); }
    static String capturePath() { return lastCapture == null ? null : new File(lastCapture, "capture.pcap").getAbsolutePath(); }

    static void applyDefaults() {
        MainActivity.iface = "wlan0"; MainActivity.prefix = "";
        MainActivity.busybox = "/system/bin/toybox";
        MainActivity.enable_monMode = ":"; MainActivity.disable_monMode = ":";
        MainActivity.enable_on_airodump = false; MainActivity.airOnStartup = false;
        MainActivity.watchdog = false; MainActivity.update_on_startup = false; MainActivity.show_notif = false;
        MainActivity.airodump_dir = "NetHunter:/usr/sbin/airodump-ng";
        MainActivity.aireplay_dir = MainActivity.aircrack_dir = MainActivity.mdk3bf_dir = MainActivity.mdk3dos_dir = MainActivity.reaver_dir = "/system/bin/false";
    }

    static void initialize(MainActivity owner) throws IOException {
        context = owner.getApplicationContext(); activity = new WeakReference<>(owner);
        tools = new File(context.getFilesDir(), "qca-tools");
        sessions = new File(context.getFilesDir(), "qca-sessions");
        if ((!tools.isDirectory() && !tools.mkdirs()) || (!sessions.isDirectory() && !sessions.mkdirs())) throw new IOException("Cannot create QCA directories");
        for (String name : ASSETS) {
            try (InputStream in = context.getAssets().open(name); OutputStream out = new FileOutputStream(new File(tools, name))) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
            }
        }
        File[] found = sessions.listFiles(File::isDirectory);
        if (found != null) for (File item : found) {
            if (latest == null || item.getName().compareTo(latest.getName()) > 0) latest = item;
            if (new File(item, "capture.csv").length() > 0 && (lastCapture == null || item.getName().compareTo(lastCapture.getName()) > 0)) lastCapture = item;
        }
    }

    static void ready(MainActivity owner) {
        activity = new WeakReference<>(owner);
        for (int id : new int[]{R.id.nav_mdk3, R.id.nav_reaver, R.id.nav_crack, R.id.nav_custom_actions})
            owner.navigationView.getMenu().findItem(id).setVisible(false);
        if (Build.VERSION.SDK_INT >= 33) owner.requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 40);
        update(phase);
    }

    static void update(String value) {
        phase = value;
        MainActivity.runInHandler(() -> {
            MainActivity owner = activity.get();
            if (owner != null && !owner.isFinishing() && owner.getSupportActionBar() != null) owner.getSupportActionBar().setSubtitle(value);
            if (MainActivity.menu != null) {
                MainActivity.menu.findItem(R.id.stop_run).setIcon(isCapturing() ? R.drawable.stop_drawable : R.drawable.start_drawable);
                MainActivity.menu.findItem(R.id.stop_run).setTitle(isCapturing() ? R.string.stop : R.string.start);
            }
            QcaRadioService.update(value);
        });
    }

    static void message(String value) { MainActivity.runInHandler(() -> Toast.makeText(context, value, Toast.LENGTH_LONG).show()); }
    static void unsupported() { message("Monitor TX is unavailable. Use a selected client's single-frame lab test."); }
    private static String quote(String value) { return "'" + value.replace("'", "'\\''") + "'"; }
    private static void writeText(java.nio.file.Path path, String value) throws IOException {
        Files.write(path, value.getBytes(StandardCharsets.UTF_8));
    }
    private static String readText(java.nio.file.Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }
    private static String tail(File file) throws IOException {
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            byte[] bytes = new byte[(int) Math.min(in.length(), 6000)];
            in.seek(in.length() - bytes.length); in.readFully(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    static void startCapture(int channel, String bssid) {
        if (channel != 0 && channel != 6) { message("This validated profile supports channel 6 only."); return; }
        if (bssid != null && !QcaCsv.isMac(bssid)) { message("Invalid AP address"); return; }
        JSONObject request = new JSONObject();
        try { request.put("channel", 6).put("bssid", bssid == null ? "all" : bssid); }
        catch (Exception error) { message(error.toString()); return; }
        launch("capture", request);
    }

    static synchronized void launch(String operation, JSONObject request) {
        if (busy) { message("Wait for the current operation to finish restoring Wi-Fi."); return; }
        busy = true; action = operation;
        try {
            String sid = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.ROOT).format(new Date()) + "_" + operation + "_" + UUID.randomUUID().toString().substring(0, 8);
            current = new File(sessions, sid);
            if (!current.mkdir()) throw new IOException("Cannot create session directory");
            for (String name : OUTPUTS) new File(current, name).createNewFile();
            request.put("channel", 6);
            writeText(new File(current, "request.json").toPath(), request.toString(2));
            context.startForegroundService(new Intent(context, QcaRadioService.class));
            File job = current;
            update(operation.equals("capture") ? "Preparing capture · Stop cancels" : "Checking " + operation);
            WORK.execute(() -> execute(operation, job, request));
        } catch (Exception error) {
            busy = false; action = ""; current = null;
            context.stopService(new Intent(context, QcaRadioService.class));
            message(error.toString()); update("Could not start operation");
        }
    }

    private static void execute(String operation, File job, JSONObject request) {
        int code = -1;
        String errorText = "";
        ScheduledFuture<?> deadline = null;
        try (PrintWriter log = new PrintWriter(new File(job, "supervisor.log"), "UTF-8")) {
            String cmd = "/system/bin/sh " + quote(new File(tools, "qca-runner.sh").getAbsolutePath()) + " " + quote(operation) + " " + quote(job.getName()) + " " + quote(job.getAbsolutePath()) + " " + android.os.Process.myPid() + " " + quote(request.optString("bssid", "all"));
            MainActivity.last_airodump = "QCA/NetHunter channel 6, maximum 60 seconds; session " + job.getName();
            Process root = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            deadline = TIMER.schedule(() -> {
                try { writeText(new File(job, "cancel").toPath(), "timeout\n"); } catch (IOException ignored) { }
                root.destroy();
            }, 150, TimeUnit.SECONDS);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(root.getInputStream(), StandardCharsets.UTF_8))) {
                String line; StringBuilder csv = null;
                while ((line = reader.readLine()) != null) {
                    log.println(line); log.flush();
                    if (line.equals("CSV_BEGIN")) { csv = new StringBuilder(); continue; }
                    if (line.equals("CSV_END")) {
                        if (csv != null) {
                            try {
                                String snapshot = new String(android.util.Base64.decode(csv.toString(), android.util.Base64.DEFAULT), StandardCharsets.UTF_8);
                                writeText(new File(job, "live.csv").toPath(), snapshot);
                                applyCsv(snapshot); lastCapture = job;
                            } catch (IllegalArgumentException invalidSnapshot) {
                                log.println("Discarded incomplete CSV snapshot");
                            }
                            csv = null;
                        }
                        continue;
                    }
                    if (csv != null) { if (csv.length() < 2_000_000) csv.append(line).append('\n'); continue; }
                    if (line.startsWith("PHASE:")) update(line.substring(6));
                    if (line.startsWith("READY:")) update(line.substring(6));
                    if (line.startsWith("ERROR:")) errorText = line.substring(6);
                }
            }
            code = root.waitFor();
        } catch (Exception error) { errorText = error.toString(); }
        finally {
            if (deadline != null) deadline.cancel(false);
            latest = job;
            if (new File(job, "capture.csv").length() > 0) lastCapture = job;
            try { writeText(new File(job, "completion.json").toPath(), new JSONObject().put("exit_code", code).put("error", errorText).put("finished_epoch_ms", System.currentTimeMillis()).toString(2)); }
            catch (Exception ignored) { }
            busy = false; action = ""; current = null;
            context.stopService(new Intent(context, QcaRadioService.class));
        }
        if (code == 0) {
            update(operation.equals("capture") ? "Capture saved · Wi-Fi setting restored" : operation + " complete");
            if (!operation.equals("capture")) showResult(job);
        } else if (code == 130) update("Cancelled · restoration finished; see session log");
        else {
            update("Operation failed · inspect logs / Restore Wi-Fi");
            message(errorText.isEmpty() ? "See latest session log for exit " + code : errorText);
            showResult(job);
        }
    }

    static void applyCsv(String text) {
        QcaCsv parsed = QcaCsv.parse(text);
        MainActivity.runInHandler(() -> {
            for (QcaCsv.AccessPoint ap : parsed.aps) Airodump.addAP(ap.ssid, ap.mac, ap.privacy, ap.cipher, ap.auth, ap.power, ap.beacons, ap.data, 0, ap.channel);
            for (QcaCsv.Station st : parsed.stations) Airodump.addST(st.mac, st.bssid != null && AP.getAPByMac(st.bssid) != null ? st.bssid : null, st.probes, st.power, 0, st.frames);
        });
    }

    static void cancel() {
        File job = current;
        if (job != null && busy) {
            try { writeText(new File(job, "cancel").toPath(), "user\n"); update("Cancelling · restoring Wi-Fi"); }
            catch (IOException error) { message(error.toString()); }
        }
    }

    static PopupMenu apMenu(MainActivity owner, View view, AP ap) {
        PopupMenu popup = new PopupMenu(owner, view);
        popup.getMenu().add("Info").setOnMenuItemClickListener(item -> { ap.showInfo(owner.getFragmentManager()); return true; });
        popup.getMenu().add("Capture this AP · 60 seconds").setOnMenuItemClickListener(item -> { startCapture(ap.ch, ap.mac); return true; });
        return popup;
    }

    static PopupMenu stationMenu(MainActivity owner, View view, ST st) {
        PopupMenu popup = new PopupMenu(owner, view);
        popup.getMenu().add("Info").setOnMenuItemClickListener(item -> { st.showInfo(owner.getFragmentManager()); return true; });
        if (st.bssid != null) popup.getMenu().add("Single-frame lab test…").setOnMenuItemClickListener(item -> { confirmLab(owner, st); return true; });
        return popup;
    }

    static void confirmLab(MainActivity owner, ST station) {
        if (busy) { message("Stop capture and wait for Wi-Fi restoration before the lab test."); return; }
        File source = lastCapture;
        if (source == null || station.bssid == null) { message("Capture the AP/client association first."); return; }
        String ap = station.bssid, client = station.mac;
        LinearLayout content = new LinearLayout(owner); content.setOrientation(LinearLayout.VERTICAL); content.setPadding(40, 16, 40, 16);
        TextView text = new TextView(owner);
        text.setText("AP: " + ap + "\nClient: " + client + "\nChannel 6 · one directed deauthentication frame\n\nUses managed wlan0. The driver ACK does not prove a disconnect. PMF may reject the frame. No automatic retry.");
        content.addView(text);
        CheckBox owned = new CheckBox(owner); owned.setText("I own or am authorized to test this AP and client."); content.addView(owned);
        AlertDialog dialog = new AlertDialog.Builder(owner).setTitle("Authorized hardware only").setView(content)
            .setNegativeButton("Cancel", null).setPositiveButton("Send one frame", (d, w) -> {
                try { launch("lab", new JSONObject().put("channel", 6).put("ap", ap).put("client", client)
                    .put("capture_session", source.getName()).put("authorized_owned_hardware", owned.isChecked())); }
                catch (Exception error) { message(error.toString()); }
            }).create();
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
            owned.setOnCheckedChangeListener((button, checked) -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(checked));
        });
        dialog.show();
    }

    static void configureMenu(Menu menu) {
        for (int id : new int[]{R.id.stop_aireplay, R.id.copy_aireplay, R.id.copy_mdk, R.id.copy_reaver}) menu.findItem(id).setVisible(false);
        menu.findItem(R.id.export).setTitle("Export latest session…");
        menu.findItem(R.id.settings).setTitle("Internal radio support");
        menu.add(0, PROBE, 20, "Check radio and NetHunter");
        menu.add(0, RESTORE, 21, "Restore Wi-Fi");
        menu.add(0, INFO, 22, "Latest result / log");
    }

    static boolean onMenu(MainActivity owner, int id) {
        if (id == R.id.settings) { showInfo(owner); return true; }
        if (id == R.id.export || id == SHARE) { exportLatest(); return true; }
        if (id == RESTORE || id == PROBE) { launch(id == RESTORE ? "restore" : "probe", new JSONObject()); return true; }
        if (id == INFO) { if (latest != null) showResult(latest); else message("No sessions yet"); return true; }
        if (id == R.id.reset) {
            if (busy) message("Stop capture before clearing the display.");
            else { Tile.clear(); Tile.onCountsChanged(); }
            return true;
        }
        return false;
    }

    static void showInfo(MainActivity owner) {
        new AlertDialog.Builder(owner).setTitle("Hijacker QCA Lab · experimental")
            .setMessage("OnePlus CPH2655 · Android 16.0.8.301\nqca_cld3_peach_v2 · NetHunter ARM64\n\nStart: channel-6 passive capture, up to 60 seconds. Wi-Fi disconnects during capture and is restored afterward. Tap a client after stopping for a single-frame lab test.\n\nMonitor TX / standard aireplay injection, channel hopping, Reaver and MDK are unavailable. Root and a running NetHunter chroot are required.\n\nUse Restore Wi-Fi after an interrupted session. This fork requires real-phone validation; see the source validation record.")
            .setPositiveButton("OK", null).show();
    }

    private static void showResult(File job) {
        MainActivity.runInHandler(() -> {
            MainActivity owner = activity.get(); if (owner == null || owner.isFinishing()) return;
            try {
                String result = readText(new File(job, "result.json").toPath());
                String completion = readText(new File(job, "completion.json").toPath());
                String radio = readText(new File(job, "radio-state.json").toPath());
                String log = tail(new File(job, "supervisor.log"));
                TextView text = new TextView(owner); text.setPadding(32, 16, 32, 16); text.setTextIsSelectable(true);
                text.setText(job.getName() + "\n\n" + completion + "\n\n" + radio + "\n\n" + result + "\n\n" + log);
                android.widget.ScrollView scroll = new android.widget.ScrollView(owner); scroll.addView(text);
                new AlertDialog.Builder(owner).setTitle("Session evidence").setView(scroll).setPositiveButton("OK", null).show();
            } catch (IOException error) { message(error.toString()); }
        });
    }

    static void exportLatest() {
        if (busy || latest == null) { message("Finish a session before exporting."); return; }
        File job = latest;
        WORK.execute(() -> {
            try {
                File exports = new File(context.getFilesDir(), "qca-exports"); if (!exports.isDirectory() && !exports.mkdir()) throw new IOException("Cannot create export directory");
                File zip = new File(exports, job.getName() + ".zip");
                try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zip))) {
                    File[] files = job.listFiles(File::isFile);
                    if (files != null) for (File file : files) {
                        if (file.length() == 0 || file.getName().equals("cancel")) continue;
                        out.putNextEntry(new ZipEntry(file.getName())); Files.copy(file.toPath(), out); out.closeEntry();
                    }
                }
                MainActivity.runInHandler(() -> {
                    MainActivity owner = activity.get(); if (owner == null || owner.isFinishing()) return;
                    Intent send = new Intent(Intent.ACTION_SEND).setType("application/zip")
                        .putExtra(Intent.EXTRA_STREAM, FileProvider.getUriForFile(context, BuildConfig.APPLICATION_ID + ".provider", zip))
                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    owner.startActivity(Intent.createChooser(send, "Export private session evidence"));
                });
            } catch (Exception error) { message(error.toString()); }
        });
    }
}
