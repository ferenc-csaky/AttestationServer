package app.attestation.server;

import com.google.common.io.BaseEncoding;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.BeanHandler;
import org.apache.commons.dbutils.handlers.BeanListHandler;
import org.apache.commons.dbutils.handlers.ColumnListHandler;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import app.attestation.server.dto.AccountAlertDTO;
import app.attestation.server.dto.AlertConfigDTO;
import app.attestation.server.dto.DeviceAlertDTO;

@SuppressWarnings({"SqlNoDataSourceInspection", "SqlResolve"})
class AlertDispatcher implements Runnable {
    private static final long WAIT_MS = 15 * 60 * 1000;
    private static final int TIMEOUT_MS = 30 * 1000;
    private static final long ALERT_THROTTLE_MS = 24 * 60 * 60 * 1000;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    private static final String SELECT_EMAILS_QUERY = "SELECT address FROM EmailAddresses WHERE userId = ?";

    @Override
    public void run() {
        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            System.err.println("dispatching alerts");

            try {
                AlertConfigDTO config = runner.query(
                        "SELECT (SELECT value FROM Configuration WHERE key = 'emailLocal') AS local, " +
                                "(SELECT value FROM Configuration WHERE key = 'emailUsername') AS username, " +
                                "(SELECT value FROM Configuration WHERE key = 'emailPassword') AS password, " +
                                "(SELECT value FROM Configuration WHERE key = 'emailHost') AS host, " +
                                "(SELECT value FROM Configuration WHERE key = 'emailPort') AS port",
                        new BeanHandler<>(AlertConfigDTO.class));

                final Session session;
                if (config.getLocal() == 1) {
                    if (config.getUsername() == null) {
                        System.err.println("missing email configuration");
                        continue;
                    }
                    final Properties props = new Properties();
                    props.put("mail.smtp.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.writetimeout", Integer.toString(TIMEOUT_MS));
                    session = Session.getInstance(props);
                } else {
                    if (!config.isComplete()) {
                        System.err.println("missing email configuration");
                        continue;
                    }

                    final Properties props = new Properties();
                    props.put("mail.transport.protocol.rfc822", "smtps");
                    props.put("mail.smtps.auth", true);
                    props.put("mail.smtps.host", config.getHost());
                    props.put("mail.smtps.port", config.getPort());
                    props.put("mail.smtps.ssl.checkserveridentity", true);
                    props.put("mail.smtps.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.writetimeout", Integer.toString(TIMEOUT_MS));

                    session = Session.getInstance(props,
                            new javax.mail.Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(config.getUsername(), config.getPassword());
                                }
                            });
                }

                List<AccountAlertDTO> accounts = runner.query("SELECT userId, alertDelay FROM Accounts",
                        new BeanListHandler<>(AccountAlertDTO.class));

                for (AccountAlertDTO account : accounts) {
                    final long now = System.currentTimeMillis();

                    long oldestExpiredTimeLast = now;
                    final List<byte[]> expiredFingerprints = new ArrayList<>();
                    final StringBuilder expired = new StringBuilder();

                    List<DeviceAlertDTO> expiredDevices = runner.query(
                            "SELECT fingerprint, expiredTimeLast FROM Devices " +
                                    "WHERE userId = ? AND verifiedTimeLast < ? AND deletionTime IS NULL",
                            new BeanListHandler<>(DeviceAlertDTO.class), account.getUserId(),
                            now - account.getAlertDelay() * 1000);

                    for (DeviceAlertDTO expiredDevice : expiredDevices) {
                        expiredFingerprints.add(expiredDevice.getFingerprint());
                        oldestExpiredTimeLast = Math.min(oldestExpiredTimeLast, expiredDevice.getExpiredTimeLast());

                        expired.append("* ");

                        final String encoded = BaseEncoding.base16().encode(expiredDevice.getFingerprint());

                        for (int i = 0; i < encoded.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
                            expired.append(encoded, i, Math.min(encoded.length(), i + FINGERPRINT_SPLIT_INTERVAL));
                            if (i + FINGERPRINT_SPLIT_INTERVAL < encoded.length()) {
                                expired.append("-");
                            }
                        }

                        expired.append("\n");
                    }

                    if (!expiredFingerprints.isEmpty() && oldestExpiredTimeLast < now - ALERT_THROTTLE_MS) {
                        List<String> addresses = runner.query(SELECT_EMAILS_QUERY, new ColumnListHandler<>(),
                                account.getUserId());

                        for (String address : addresses) {
                            System.err.println("sending email to " + address);
                            try {
                                final Message message = new MimeMessage(session);
                                message.setFrom(new InternetAddress(config.getUsername()));
                                message.setRecipients(Message.RecipientType.TO,
                                        InternetAddress.parse(address));
                                message.setSubject(
                                        "Devices failed to provide valid attestations within " +
                                                account.getAlertDelay() / 60 / 60 + " hours");
                                message.setText("The following devices have failed to provide valid attestations before the expiry time:\n\n" +
                                        expired.toString() + "\nLog in to https://attestation.app/ for more information.");

                                Transport.send(message);

                                for (final byte[] fingerprint : expiredFingerprints) {
                                    runner.update("UPDATE Devices SET expiredTimeLast = ? WHERE fingerprint = ?",
                                            now, fingerprint);
                                }
                            } catch (final MessagingException e) {
                                e.printStackTrace();
                            }
                        }
                    }

                    final StringBuilder failed = new StringBuilder();

                    List<byte[]> failedFingerprints = runner.query("SELECT fingerprint FROM Devices " +
                                    "WHERE userId = ? AND failureTimeLast IS NOT NULL AND deletionTime IS NULL",
                            new ColumnListHandler<>(), account.getUserId());

                    for (byte[] failedFingerprint : failedFingerprints) {
                        final String encoded = BaseEncoding.base16().encode(failedFingerprint);
                        failed.append("* ").append(encoded).append("\n");
                    }

                    if (failed.length() > 0) {
                        List<String> addresses = runner.query(SELECT_EMAILS_QUERY, new ColumnListHandler<>(),
                                account.getUserId());

                        for (String address : addresses) {
                            System.err.println("sending email to " + address);
                            try {
                                final Message message = new MimeMessage(session);
                                message.setFrom(new InternetAddress(config.getUsername()));
                                message.setRecipients(Message.RecipientType.TO,
                                        InternetAddress.parse(address));
                                message.setSubject("Devices provided invalid attestations");
                                message.setText("The following devices have provided invalid attestations:\n\n" +
                                        failed.toString());

                                Transport.send(message);
                            } catch (final MessagingException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}
