/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.hijacker;

import android.app.*;
import android.content.Intent;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;

public final class QcaRadioService extends Service {
    private static QcaRadioService active;
    private static final int ID = 2001;
    @Override public void onCreate() {
        super.onCreate(); active = this;
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("qca-radio", "Internal radio session", NotificationManager.IMPORTANCE_LOW));
        startForeground(ID, notification("Preparing bounded radio operation"));
    }
    private Notification notification(String text) {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, QcaRadioService.class).setAction("stop"), PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, "qca-radio").setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Hijacker QCA Lab").setContentText(text).setContentIntent(open).setOngoing(true)
            .addAction(R.drawable.stop_drawable, "Stop and restore", stop).build();
    }
    static void update(String text) { if (active != null) active.getSystemService(NotificationManager.class).notify(ID, active.notification(text)); }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "stop".equals(intent.getAction())) QcaBackend.cancel();
        return START_NOT_STICKY;
    }
    @Override public void onTaskRemoved(Intent intent) { QcaBackend.cancel(); }
    @Override public void onDestroy() { active = null; super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return null; }
}
