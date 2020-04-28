package app.attestation.server;

import com.almworks.sqlite4java.SQLiteBackup;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;

class Maintenance implements Runnable {
    private static final File ATTESTATION_DB_FILE = new File(AttestationProtocol.ATTESTATION_DB);
    private static final long WAIT_MS = 24 * 60 * 60 * 1000;
    private static final int DELETE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

    @Override
    public void run() {
        final SQLiteConnection conn = new SQLiteConnection(ATTESTATION_DB_FILE);
        final SQLiteStatement deleteDeletedDevices;
        final SQLiteStatement selectBackups;
        final SQLiteStatement updateBackups;
        try {
            open(conn, false);
            deleteDeletedDevices = conn.prepare("DELETE FROM Devices WHERE deletionTime < ?");
            selectBackups = conn.prepare("SELECT value FROM Configuration WHERE key = 'backups'");
            updateBackups = conn.prepare("UPDATE Configuration SET value = value + 1 " +
                    "WHERE key = 'backups'");
        } catch (final SQLiteException e) {
            conn.dispose();
            throw new RuntimeException(e);
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            System.err.println("maintenance");

            try {
                deleteDeletedDevices.bind(1, System.currentTimeMillis() - DELETE_EXPIRY_MS);
                deleteDeletedDevices.step();

                selectBackups.step();
                final long backups = selectBackups.columnLong(0);

                updateBackups.step();
                final SQLiteBackup backup = conn.initializeBackup(new File("backup/" + backups + ".db"));
                try {
                    backup.backupStep(-1);
                } finally {
                    backup.dispose();
                }
            } catch (final SQLiteException e) {
                e.printStackTrace();
            } finally {
                try {
                    deleteDeletedDevices.reset();
                    selectBackups.reset();
                    updateBackups.reset();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void open(final SQLiteConnection conn, final boolean readOnly) throws SQLiteException {
        if (readOnly) {
            conn.openReadonly();
        } else {
            conn.open();
        }
        conn.setBusyTimeout(SQLUtil.BUSY_TIMEOUT);
        conn.exec("PRAGMA foreign_keys=ON");
        conn.exec("PRAGMA journal_mode=WAL");
    }
}
