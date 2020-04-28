package app.attestation.server;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.apache.commons.dbutils.DbUtils;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.BeanHandler;
import org.apache.commons.dbutils.handlers.BeanListHandler;
import org.apache.commons.dbutils.handlers.ScalarHandler;
import org.bouncycastle.crypto.generators.SCrypt;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.zip.DataFormatException;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import app.attestation.server.AttestationProtocol.DeviceInfo;
import app.attestation.server.dto.AttestationDTO;
import app.attestation.server.dto.DeviceDTO;
import app.attestation.server.dto.LoginDTO;
import app.attestation.server.dto.PasswordDTO;
import app.attestation.server.dto.SessionDTO;
import app.attestation.server.dto.VerifyDTO;

import static com.almworks.sqlite4java.SQLiteConstants.SQLITE_CONSTRAINT_UNIQUE;

import static app.attestation.server.AttestationProtocol.fingerprintsCustomOS;
import static app.attestation.server.AttestationProtocol.fingerprintsStock;
import static app.attestation.server.AttestationProtocol.fingerprintsStrongBoxCustomOS;
import static app.attestation.server.AttestationProtocol.fingerprintsStrongBoxStock;

@SuppressWarnings({"SqlNoDataSourceInspection", "SqlResolve"})
public class AttestationServer {
    private static final String SAMPLES_DB = "samples.db";
    private static final int DEFAULT_VERIFY_INTERVAL = 4 * 60 * 60;
    private static final int MIN_VERIFY_INTERVAL = 60 * 60;
    private static final int MAX_VERIFY_INTERVAL = 7 * 24 * 70 * 60;
    private static final int DEFAULT_ALERT_DELAY = 48 * 60 * 60;
    private static final int MIN_ALERT_DELAY = 32 * 60 * 60;
    private static final int MAX_ALERT_DELAY = 2 * 7 * 24 * 60 * 60;
    private static final int QR_CODE_SIZE = 300;
    private static final long SESSION_LENGTH = 48 * 60 * 60 * 1000;

    private static final Cache<ByteBuffer, Boolean> pendingChallenges = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();

    public static void main(final String[] args) throws Exception {

        QueryRunner samplesRunner = SQLUtil.initQueryRunner(SAMPLES_DB, false);
        QueryRunner attestationRunner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);

        samplesRunner.update("CREATE TABLE IF NOT EXISTS Samples (\n" +
                    "sample TEXT NOT NULL,\n" +
                    "time INTEGER NOT NULL\n" +
                    ")");
        samplesRunner.update("VACUUM");

        attestationRunner.update("CREATE TABLE IF NOT EXISTS Configuration (\n" +
                    "key TEXT PRIMARY KEY NOT NULL,\n" +
                    "value NOT NULL\n" +
                    ")");
        attestationRunner.update("INSERT OR IGNORE INTO Configuration " +
                    "(key, value) VALUES ('backups', 0)");
        attestationRunner.update(
                    "CREATE TABLE IF NOT EXISTS Accounts (\n" +
                    "userId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n" +
                    "username TEXT NOT NULL UNIQUE,\n" +
                    "passwordHash BLOB NOT NULL,\n" +
                    "passwordSalt BLOB NOT NULL,\n" +
                    "subscribeKey BLOB NOT NULL,\n" +
                    "creationTime INTEGER NOT NULL,\n" +
                    "verifyInterval INTEGER NOT NULL,\n" +
                    "alertDelay INTEGER NOT NULL\n" +
                    ")");
        attestationRunner.update(
                    "CREATE TABLE IF NOT EXISTS EmailAddresses (\n" +
                    "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                    "address TEXT NOT NULL,\n" +
                    "PRIMARY KEY (userId, address)\n" +
                    ")");
        attestationRunner.update(
                    "CREATE TABLE IF NOT EXISTS Sessions (\n" +
                    "sessionId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n" +
                    "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                    "cookieToken BLOB NOT NULL,\n" +
                    "requestToken BLOB NOT NULL,\n" +
                    "expiryTime INTEGER NOT NULL\n" +
                    ")");
        attestationRunner.update("CREATE INDEX IF NOT EXISTS Sessions_expiryTime " +
                    "ON Sessions (expiryTime)");
        attestationRunner.update("CREATE INDEX IF NOT EXISTS Sessions_userId " +
                    "ON Sessions (userId)");
        attestationRunner.update(
                    "CREATE TABLE IF NOT EXISTS Devices (\n" +
                    "fingerprint BLOB NOT NULL PRIMARY KEY,\n" +
                    "pinnedCertificate0 BLOB NOT NULL,\n" +
                    "pinnedCertificate1 BLOB NOT NULL,\n" +
                    "pinnedCertificate2 BLOB NOT NULL,\n" +
                    "pinnedVerifiedBootKey BLOB NOT NULL,\n" +
                    "verifiedBootHash BLOB,\n" +
                    "pinnedOsVersion INTEGER NOT NULL,\n" +
                    "pinnedOsPatchLevel INTEGER NOT NULL,\n" +
                    "pinnedVendorPatchLevel INTEGER,\n" +
                    "pinnedBootPatchLevel INTEGER,\n" +
                    "pinnedAppVersion INTEGER NOT NULL,\n" +
                    "pinnedSecurityLevel INTEGER NOT NULL,\n" +
                    "userProfileSecure INTEGER NOT NULL CHECK (userProfileSecure in (0, 1)),\n" +
                    "enrolledFingerprints INTEGER NOT NULL CHECK (enrolledFingerprints in (0, 1)),\n" +
                    "accessibility INTEGER NOT NULL CHECK (accessibility in (0, 1)),\n" +
                    "deviceAdmin INTEGER NOT NULL CHECK (deviceAdmin in (0, 1, 2)),\n" +
                    "adbEnabled INTEGER NOT NULL CHECK (adbEnabled in (0, 1)),\n" +
                    "addUsersWhenLocked INTEGER NOT NULL CHECK (addUsersWhenLocked in (0, 1)),\n" +
                    "denyNewUsb INTEGER NOT NULL CHECK (denyNewUsb in (0, 1)),\n" +
                    "oemUnlockAllowed INTEGER CHECK (oemUnlockAllowed in (0, 1)),\n" +
                    "systemUser INTEGER CHECK (systemUser in (0, 1)),\n" +
                    "verifiedTimeFirst INTEGER NOT NULL,\n" +
                    "verifiedTimeLast INTEGER NOT NULL,\n" +
                    "expiredTimeLast INTEGER,\n" +
                    "failureTimeLast INTEGER,\n" +
                    "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                    "deletionTime INTEGER\n" +
                    ")");
            try {
                attestationRunner.update("ALTER TABLE Devices ADD COLUMN pinnedSecurityLevel INTEGER NOT NULL DEFAULT 1");
            } catch (SQLException ignored) {
            }
            try {
                attestationRunner.update("ALTER TABLE Devices ADD COLUMN verifiedBootHash BLOB");
            } catch (SQLException ignored) {
            }
            try {
                attestationRunner.update("ALTER TABLE Devices ADD COLUMN expiredTimeLast INTEGER");
            } catch (SQLException ignored) {
            }
            try {
                attestationRunner.update("ALTER TABLE Devices ADD COLUMN systemUser INTEGER CHECK (systemUser in (0, 1))");
            } catch (SQLException ignored) {
            }
            attestationRunner.update("CREATE INDEX IF NOT EXISTS Devices_userId_verifiedTimeFirst " +
                    "ON Devices (userId, verifiedTimeFirst)");
            attestationRunner.update("CREATE INDEX IF NOT EXISTS Devices_userId_verifiedTimeLast " +
                    "ON Devices (userId, verifiedTimeLast)");
            attestationRunner.update("CREATE INDEX IF NOT EXISTS Devices_deletionTime " +
                    "ON Devices (deletionTime) WHERE deletionTime IS NOT NULL");
            attestationRunner.update(
                    "CREATE TABLE IF NOT EXISTS Attestations (\n" +
                    "fingerprint BLOB NOT NULL REFERENCES Devices (fingerprint) ON DELETE CASCADE,\n" +
                    "time BLOB NOT NULL,\n" +
                    "strong INTEGER NOT NULL CHECK (strong in (0, 1)),\n" +
                    "teeEnforced TEXT NOT NULL,\n" +
                    "osEnforced TEXT NOT NULL\n" +
                    ")");
            attestationRunner.update("CREATE INDEX IF NOT EXISTS Attestations_fingerprint_time " +
                    "ON Attestations (fingerprint, time)");
            attestationRunner.update("ANALYZE");
            attestationRunner.update("VACUUM");


        Files.createDirectories(Paths.get("backup"));

        new Thread(new AlertDispatcher()).start();
        new Thread(new Maintenance()).start();

        System.setProperty("sun.net.httpserver.nodelay", "true");
        final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
        server.createContext("/api/create_account", new CreateAccountHandler());
        server.createContext("/api/change_password", new ChangePasswordHandler());
        server.createContext("/api/login", new LoginHandler());
        server.createContext("/api/logout", new LogoutHandler());
        server.createContext("/api/logout_everywhere", new LogoutEverywhereHandler());
        server.createContext("/api/rotate", new RotateHandler());
        server.createContext("/api/account", new AccountHandler());
        server.createContext("/api/account.png", new AccountQrHandler());
        server.createContext("/api/configuration", new ConfigurationHandler());
        server.createContext("/api/delete_device", new DeleteDeviceHandler());
        server.createContext("/api/devices.json", new DevicesHandler());
        server.createContext("/challenge", new ChallengeHandler());
        server.createContext("/verify", new VerifyHandler());
        server.createContext("/submit", new SubmitHandler());
        server.setExecutor(new ThreadPoolExecutor(10, 100, 60, TimeUnit.SECONDS, new SynchronousQueue<>()));
        server.start();
    }

    private abstract static class PostHandler implements HttpHandler {
        protected abstract void handlePost(final HttpExchange exchange) throws IOException, SQLException;

        @Override
        public final void handle(final HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            try {
                handlePost(exchange);
            } catch (final Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
            }
        }
    }

    private static final SecureRandom random = new SecureRandom();

    private static byte[] generateRandomToken() {
        final byte[] token = new byte[32];
        random.nextBytes(token);
        return token;
    }

    private static byte[] hash(final byte[] password, final byte[] salt) {
        return SCrypt.generate(password, salt, 32768, 8, 1, 32);
    }

    private static class UsernameUnavailableException extends GeneralSecurityException {
        public UsernameUnavailableException() {}
    }

    private static void validatePassword(final String password) throws GeneralSecurityException {
        if (password.length() < 8 || password.length() > 4096) {
            throw new GeneralSecurityException("invalid password");
        }
    }

    private static void createAccount(final String username, final String password)
            throws GeneralSecurityException, SQLException {
        if (username.length() > 32 || !username.matches("[a-zA-Z0-9]+")) {
            throw new GeneralSecurityException("invalid username");
        }
        validatePassword(password);

        final byte[] passwordSalt = generateRandomToken();
        final byte[] passwordHash = hash(password.getBytes(), passwordSalt);
        final byte[] subscribeKey = generateRandomToken();

        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);
        try {
            runner.update("INSERT INTO Accounts " +
                    "(username, passwordHash, passwordSalt, subscribeKey, creationTime, verifyInterval, alertDelay) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", username, passwordHash, passwordSalt, subscribeKey,
                    System.currentTimeMillis(), DEFAULT_VERIFY_INTERVAL, DEFAULT_ALERT_DELAY);

        } catch (SQLException e) {
            if (e.getErrorCode() == SQLITE_CONSTRAINT_UNIQUE) {
                throw new UsernameUnavailableException();
            }
            throw e;
        }
    }

    private static void changePassword(final long userId, final String currentPassword, final String newPassword)
            throws GeneralSecurityException, SQLException {
        validatePassword(currentPassword);
        validatePassword(newPassword);

        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);
        Connection conn = null;
        try {
            conn = SQLUtil.initTransaction(runner);

            PasswordDTO stored = runner.query(conn, "SELECT passwordHash, passwordSalt FROM Accounts WHERE userId = ?",
                    new BeanHandler<>(PasswordDTO.class), userId);

            if (stored == null) {
                throw new GeneralSecurityException("user not found");
            }

            if (!MessageDigest.isEqual(hash(currentPassword.getBytes(), stored.getPasswordSalt()), stored.getPasswordHash())) {
                throw new GeneralSecurityException("invalid password");
            }

            byte[] newPasswordSalt = generateRandomToken();
            byte[] newPasswordHash = hash(newPassword.getBytes(), newPasswordSalt);

            runner.update(conn, "UPDATE Accounts SET passwordHash = ?, passwordSalt = ? WHERE userId = ?",
                    newPasswordHash, newPasswordSalt, userId);

            DbUtils.commitAndClose(conn);

        } catch (Exception e) {
            DbUtils.rollbackAndClose(conn);
            throw e;
        }
    }

    private static class Session {
        final long sessionId;
        final byte[] cookieToken;
        final byte[] requestToken;

        Session(final long sessionId, final byte[] cookieToken, final byte[] requestToken) {
            this.sessionId = sessionId;
            this.cookieToken = cookieToken;
            this.requestToken = requestToken;
        }
    }

    private static Session login(final String username, final String password)
            throws GeneralSecurityException, SQLException {
        validatePassword(password);

        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);

        LoginDTO login = runner.query("SELECT userId, passwordHash, passwordSalt FROM Accounts WHERE username = ?",
                new BeanHandler<>(LoginDTO.class), username);

        if (login == null) {
            throw new UsernameUnavailableException();
        }

        if (!MessageDigest.isEqual(hash(password.getBytes(), login.getPasswordSalt()), login.getPasswordHash())) {
            throw new GeneralSecurityException("invalid password");
        }

        long now = System.currentTimeMillis();
        runner.update("DELETE FROM Sessions WHERE expiryTime < ?", now);

        final byte[] cookieToken = generateRandomToken();
        final byte[] requestToken = generateRandomToken();

        Connection conn = null;
        try {
            conn = SQLUtil.initTransaction(runner);

            runner.update(conn, "INSERT INTO Sessions (userId, cookieToken, requestToken, expiryTime) VALUES (?, ?, ?, ?)",
                    login.getUserId(), cookieToken, requestToken, now + SESSION_LENGTH);

            long sessionId = runner.query(conn, "SELECT sessionId FROM Sessions WHERE userId = ? AND expiryTime = ?",
                    new ScalarHandler<>(), login.getUserId(), now + SESSION_LENGTH);

            DbUtils.commitAndClose(conn);

            return new Session(sessionId, cookieToken, requestToken);

        } catch (Exception e) {
            DbUtils.rollbackAndClose(conn);
            throw e;
        }
    }

    private static class CreateAccountHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final String username;
            final String password;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                username = object.getString("username");
                password = object.getString("password");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            try {
                createAccount(username, password);
            } catch (final UsernameUnavailableException e) {
                exchange.sendResponseHeaders(409, -1);
                return;
            } catch (final GeneralSecurityException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class ChangePasswordHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final String requestToken;
            final String currentPassword;
            final String newPassword;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                requestToken = object.getString("requestToken");
                currentPassword = object.getString("currentPassword");
                newPassword = object.getString("newPassword");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false, requestToken.getBytes(StandardCharsets.UTF_8));
            if (account == null) {
                return;
            }

            try {
                changePassword(account.userId, currentPassword, newPassword);
            } catch (final GeneralSecurityException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class LoginHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final String username;
            final String password;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                username = object.getString("username");
                password = object.getString("password");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Session session;
            try {
                session = login(username, password);
            } catch (final UsernameUnavailableException e) {
                exchange.sendResponseHeaders(400, -1);
                return;
            } catch (final GeneralSecurityException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(403, -1);
                return;
            }

            final Base64.Encoder encoder = Base64.getEncoder();
            final byte[] requestToken = encoder.encode(session.requestToken);
            exchange.getResponseHeaders().set("Set-Cookie",
                    String.format("__Host-session=%d|%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d",
                        session.sessionId, new String(encoder.encode(session.cookieToken)),
                        SESSION_LENGTH / 1000));
            exchange.sendResponseHeaders(200, requestToken.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(requestToken);
            }
        }
    }

    private static class LogoutHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, true, null);
            if (account == null) {
                return;
            }
            clearCookie(exchange);
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class LogoutEverywhereHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, false, null);
            if (account == null) {
                return;
            }
            SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false)
                    .update("DELETE from Sessions where userId = ?", account.userId);
            clearCookie(exchange);
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class RotateHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, false, null);
            if (account == null) {
                return;
            }
            byte[] subscribeKey = generateRandomToken();
            QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);
            runner.update("UPDATE Accounts SET subscribeKey = ? WHERE userId = ?",
                    subscribeKey, account.userId);
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static String getCookie(final HttpExchange exchange, final String key) {
        final List<String> cookieHeaders = exchange.getRequestHeaders().get("Cookie");
        if (cookieHeaders == null) {
            return null;
        }
        for (final String cookieHeader : cookieHeaders) {
            final String[] cookies = cookieHeader.split(";");
            for (final String cookie : cookies) {
                final String[] keyValue = cookie.trim().split("=", 2);
                if (keyValue.length == 2) {
                    if (keyValue[0].equals(key)) {
                        return keyValue[1];
                    }
                }
            }
        }
        return null;
    }

    private static class Account {
        final long userId;
        final String username;
        final byte[] subscribeKey;
        final int verifyInterval;
        final int alertDelay;

        Account(final long userId, final String username, final byte[] subscribeKey,
                final int verifyInterval, final int alertDelay) {
            this.userId = userId;
            this.username = username;
            this.subscribeKey = subscribeKey;
            this.verifyInterval = verifyInterval;
            this.alertDelay = alertDelay;
        }
    }

    private static void clearCookie(final HttpExchange exchange) {
        exchange.getResponseHeaders().set("Set-Cookie",
                "__Host-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
    }

    private static Account verifySession(final HttpExchange exchange, final boolean end,
                                         final byte[] requestTokenEncoded) throws IOException, SQLException {
        final String cookie = getCookie(exchange, "__Host-session");
        if (cookie == null) {
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final String[] session = cookie.split("\\|", 2);
        if (session.length != 2) {
            clearCookie(exchange);
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final long sessionId = Long.parseLong(session[0]);
        final byte[] cookieToken = Base64.getDecoder().decode(session[1]);

        byte[] requestTokenEncodedVal;
        if (requestTokenEncoded == null) {
            requestTokenEncodedVal = new byte[session[1].length()];
            final DataInputStream input = new DataInputStream(exchange.getRequestBody());
            try {
                input.readFully(requestTokenEncodedVal);
            } catch (final EOFException e) {
                clearCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }
        } else {
            requestTokenEncodedVal = requestTokenEncoded;
        }
        final byte[] requestToken = Base64.getDecoder().decode(requestTokenEncodedVal);

        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, !end);

        SessionDTO sessionData = runner.query("SELECT cookieToken, requestToken, " +
                    "expiryTime, username, subscribeKey, Accounts.userId, verifyInterval, alertDelay " +
                    "FROM Sessions " +
                    "INNER JOIN Accounts on Accounts.userId = Sessions.userId " +
                    "WHERE sessionId = ?", new BeanHandler<>(SessionDTO.class), sessionId);

        if (!MessageDigest.isEqual(cookieToken, sessionData.getCookieToken())
                || !MessageDigest.isEqual(requestToken, sessionData.getRequestToken())
                || sessionData.getExpiryTime() < System.currentTimeMillis()) {
            clearCookie(exchange);
            exchange.sendResponseHeaders(403, -1);
            return null;
        }

        if (end) {
            runner.update("DELETE FROM Sessions WHERE sessionId = ?", sessionId);
        }

        return new Account(sessionData.getUserId(), sessionData.getUsername(), sessionData.getSubscribeKey(),
                sessionData.getVerifyInterval(), sessionData.getAlertDelay());
    }

    private static class AccountHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, false, null);
            if (account == null) {
                return;
            }
            final JsonObjectBuilder accountJson = Json.createObjectBuilder();
            accountJson.add("username", account.username);
            accountJson.add("verifyInterval", account.verifyInterval);
            accountJson.add("alertDelay", account.alertDelay);

            QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, true);
            String email = runner.query("SELECT address FROM EmailAddresses WHERE userId = ?",
                    new ScalarHandler<>(), account.userId);
            accountJson.add("email", email);

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            try (final OutputStream output = exchange.getResponseBody();
                    final JsonWriter writer = Json.createWriter(output)) {
                writer.write(accountJson.build());
            }
        }
    }

    private static void createQrCode(final byte[] contents, final OutputStream output) throws IOException {
        final BitMatrix result;
        try {
            final QRCodeWriter writer = new QRCodeWriter();
            final Map<EncodeHintType,Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, "ISO-8859-1");
            result = writer.encode(new String(contents, StandardCharsets.ISO_8859_1),
                    BarcodeFormat.QR_CODE, QR_CODE_SIZE, QR_CODE_SIZE, hints);
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }

        MatrixToImageWriter.writeToStream(result, "png", output);
    }

    private static class AccountQrHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, false, null);
            if (account == null) {
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", "image/png");
            exchange.sendResponseHeaders(200, 0);
            try (final OutputStream output = exchange.getResponseBody()) {
                final String contents = "attestation.app " +
                    account.userId + " " +
                    BaseEncoding.base64().encode(account.subscribeKey) + " " +
                    account.verifyInterval;
                createQrCode(contents.getBytes(), output);
            }
        }
    }

    private static class ConfigurationHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final int verifyInterval;
            final int alertDelay;
            final String email;
            final String requestToken;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                requestToken = object.getString("requestToken");
                verifyInterval = object.getInt("verifyInterval");
                alertDelay = object.getInt("alertDelay");
                email = object.getString("email");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false, requestToken.getBytes(StandardCharsets.UTF_8));
            if (account == null) {
                return;
            }

            if (verifyInterval < MIN_VERIFY_INTERVAL || verifyInterval > MAX_VERIFY_INTERVAL) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            if (alertDelay < MIN_ALERT_DELAY || alertDelay > MAX_ALERT_DELAY || alertDelay <= verifyInterval) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            if (!email.isEmpty()) {
                try {
                    new InternetAddress(email).validate();
                } catch (final AddressException e) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
            }

            QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);
            Connection conn = null;
            try {
                conn = SQLUtil.initTransaction(runner);

                runner.update(conn, "UPDATE Accounts SET verifyInterval = ?, alertDelay = ? WHERE userId = ?",
                        verifyInterval, alertDelay, account.userId);
                runner.update(conn, "DELETE FROM EmailAddresses WHERE userId = ?", account.userId);
                runner.update(conn, "INSERT INTO EmailAddresses (userId, address) VALUES (?, ?)",
                        account.userId, email);

                DbUtils.commitAndClose(conn);

            } catch (Exception e) {
                DbUtils.rollbackAndClose(conn);
                throw e;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class DeleteDeviceHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final String requestToken;
            final String fingerprint;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                requestToken = object.getString("requestToken");
                fingerprint = object.getString("fingerprint");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false, requestToken.getBytes(StandardCharsets.UTF_8));
            if (account == null) {
                return;
            }

            QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, false);
            int updatedRows = runner.update(
                    "UPDATE Devices SET deletionTime = ? WHERE userId = ? AND hex(fingerprint) = ?",
                    System.currentTimeMillis(), account.userId, fingerprint);

            if (updatedRows < 1) {
                exchange.sendResponseHeaders(400, -1);
            } else {
                exchange.sendResponseHeaders(200, -1);
            }
        }
    }

    private static String convertToPem(final byte[] derEncoded) {
        return "-----BEGIN CERTIFICATE-----\n" +
                new String(Base64.getMimeEncoder(64, "\n".getBytes()).encode(derEncoded)) +
                "\n-----END CERTIFICATE-----";
    }

    private static void writeDevicesJson(final HttpExchange exchange, final long userId)
            throws IOException, SQLException {
        String query = "SELECT fingerprint, pinnedCertificate0, pinnedCertificate1, pinnedCertificate2, " +
                "hex(pinnedVerifiedBootKey) AS verifiedBootKeyVal, " +
                "(SELECT hex(verifiedBootHash) WHERE verifiedBootHash IS NOT NULL) AS verifiedBootHashVal, " +
                "pinnedOsVersion, pinnedOsPatchLevel, pinnedVendorPatchLevel, " +
                "pinnedBootPatchLevel, pinnedAppVersion, pinnedSecurityLevel, " +
                "userProfileSecure, enrolledFingerprints, accessibility, deviceAdmin, " +
                "adbEnabled, addUsersWhenLocked, denyNewUsb, oemUnlockAllowed, " +
                "systemUser, verifiedTimeFirst, verifiedTimeLast " +
                "FROM Devices WHERE userId IS ? AND deletionTime IS NULL " +
                "ORDER BY verifiedTimeFirst";

        QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, true);
        List<DeviceDTO> devicesData = runner.query(query, new BeanListHandler<>(DeviceDTO.class), userId);
        final JsonArrayBuilder devices = Json.createArrayBuilder();
        for (DeviceDTO deviceData : devicesData) {
            JsonObjectBuilder device = Json.createObjectBuilder();
            device.add("fingerprint", BaseEncoding.base16().encode(deviceData.getFingerprint()));
            device.add("pinnedCertificate0", convertToPem(deviceData.getPinnedCertificate0()));
            device.add("pinnedCertificate1", convertToPem(deviceData.getPinnedCertificate1()));
            device.add("pinnedCertificate2", convertToPem(deviceData.getPinnedCertificate2()));
            String verifiedBootKey = deviceData.getVerifiedBootKeyVal();
            device.add("verifiedBootKey", verifiedBootKey);
            DeviceInfo info;
            int pinnedSecurityLevel = deviceData.getPinnedSecurityLevel();
            if (pinnedSecurityLevel == AttestationProtocol.SECURITY_LEVEL_STRONGBOX) {
                info = fingerprintsStrongBoxCustomOS.get(verifiedBootKey);
                if (info == null) {
                    info = fingerprintsStrongBoxStock.get(verifiedBootKey);
                    if (info == null) {
                        throw new RuntimeException("invalid fingerprint");
                    }
                }
            } else {
                info = fingerprintsCustomOS.get(verifiedBootKey);
                if (info == null) {
                    info = fingerprintsStock.get(verifiedBootKey);
                    if (info == null) {
                        throw new RuntimeException("invalid fingerprint");
                    }
                }
            }
            device.add("osName", info.osName);
            device.add("name", info.name);
            if (deviceData.getVerifiedBootHashVal() != null) {
                device.add("verifiedBootHash", deviceData.getVerifiedBootHashVal());
            }
            device.add("pinnedOsVersion", deviceData.getPinnedOsVersion());
            device.add("pinnedOsPatchLevel", deviceData.getPinnedOsPatchLevel());
            if (deviceData.getPinnedVendorPatchLevel() != null) {
                device.add("pinnedVendorPatchLevel",deviceData.getPinnedVendorPatchLevel());
            }
            if (deviceData.getPinnedBootPatchLevel() != null) {
                device.add("pinnedBootPatchLevel", deviceData.getPinnedBootPatchLevel());
            }
            device.add("pinnedAppVersion", deviceData.getPinnedAppVersion());
            device.add("pinnedSecurityLevel", pinnedSecurityLevel);
            device.add("userProfileSecure", deviceData.getUserProfileSecure());
            device.add("enrolledFingerprints", deviceData.getEnrolledFingerprints());
            device.add("accessibility", deviceData.getAccessibility());
            device.add("deviceAdmin", deviceData.getDeviceAdmin());
            device.add("adbEnabled", deviceData.getAdbEnabled());
            device.add("addUsersWhenLocked", deviceData.getAddUsersWhenLocked());
            device.add("denyNewUsb", deviceData.getDenyNewUsb());
            if (deviceData.getOemUnlockAllowed() != null) {
                device.add("oemUnlockAllowed", deviceData.getOemUnlockAllowed());
            }
            if (deviceData.getSystemUser() != null) {
                device.add("systemUser", deviceData.getSystemUser());
            }
            device.add("verifiedTimeFirst", deviceData.getVerifiedTimeFirst());
            device.add("verifiedTimeLast", deviceData.getVerifiedTimeLast());

            List<AttestationDTO> attestationsData = runner.query("SELECT time, strong, teeEnforced, osEnforced " +
                            "FROM Attestations WHERE fingerprint = ? ORDER BY time",
                    new BeanListHandler<>(AttestationDTO.class), (Object) deviceData.getFingerprint());

            JsonArrayBuilder attestations = Json.createArrayBuilder();
            for (AttestationDTO attestationData : attestationsData) {
                JsonObjectBuilder attestation = Json.createObjectBuilder()
                        .add("time", attestationData.getTime())
                        .add("strong", attestationData.getStrong() != 0)
                        .add("teeEnforced", attestationData.getTeeEnforced())
                        .add("osEnforced", attestationData.getOsEnforced());
                attestations.add(attestation);
            }
            device.add("attestations", attestations);

            devices.add(device);
        }

        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);
        try (final OutputStream output = exchange.getResponseBody();
                final JsonWriter writer = Json.createWriter(output)) {
            writer.write(devices.build());
        }
    }

    private static class DevicesHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final Account account = verifySession(exchange, false, null);
            if (account == null) {
                return;
            }
            writeDevicesJson(exchange, account.userId);
        }
    }

    private static class ChallengeHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException {
            final byte[] challenge = AttestationProtocol.getChallenge();
            pendingChallenges.put(ByteBuffer.wrap(challenge), true);

            final byte[] challengeMessage =
                    Bytes.concat(new byte[]{AttestationProtocol.PROTOCOL_VERSION},
                            new byte[AttestationProtocol.CHALLENGE_LENGTH], challenge);

            exchange.sendResponseHeaders(200, challengeMessage.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(challengeMessage);
            }
        }
    }

    private static class VerifyHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final List<String> authorization = exchange.getRequestHeaders().get("Authorization");
            if (authorization == null) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            final String[] tokens = authorization.get(0).split(" ");
            if (!tokens[0].equals("Auditor") || tokens.length < 2 || tokens.length > 3) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            final long userId = Long.parseLong(tokens[1]);
            final String subscribeKey = tokens.length == 3 ? tokens[2] : null;

            QueryRunner runner = SQLUtil.initQueryRunner(AttestationProtocol.ATTESTATION_DB, true);
            VerifyDTO verifyData = runner.query("SELECT subscribeKey, verifyInterval " +
                    "FROM Accounts WHERE userId = ?", new BeanHandler<>(VerifyDTO.class), userId);

            if (subscribeKey != null && !MessageDigest.isEqual(BaseEncoding.base64().decode(subscribeKey),
                    verifyData.getSubscribeKey())) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final InputStream input = exchange.getRequestBody();

            final ByteArrayOutputStream attestation = new ByteArrayOutputStream();
            final byte[] buffer = new byte[4096];
            for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                attestation.write(buffer, 0, read);

                if (attestation.size() > AttestationProtocol.MAX_MESSAGE_SIZE) {
                    final byte[] response = "Attestation too large".getBytes();
                    exchange.sendResponseHeaders(400, response.length);
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response);
                    }
                    return;
                }
            }

            final byte[] attestationResult = attestation.toByteArray();

            try {
                AttestationProtocol.verifySerialized(attestationResult, pendingChallenges, userId, subscribeKey == null);
            } catch (final BufferUnderflowException | NegativeArraySizeException | DataFormatException | GeneralSecurityException | IOException e) {
                e.printStackTrace();
                final byte[] response = "Error\n".getBytes();
                exchange.sendResponseHeaders(400, response.length);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(response);
                }
                return;
            }

            final byte[] result = (BaseEncoding.base64().encode(verifyData.getSubscribeKey()) + " " +
                    verifyData.getVerifyInterval()).getBytes();
            exchange.sendResponseHeaders(200, result.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(result);
            }
        }
    }

    private static class SubmitHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLException {
            final InputStream input = exchange.getRequestBody();

            final ByteArrayOutputStream sample = new ByteArrayOutputStream();
            final byte[] buffer = new byte[4096];
            for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                sample.write(buffer, 0, read);

                if (sample.size() > 64 * 1024) {
                    exchange.sendResponseHeaders(413, -1);
                    return;
                }
            }

            QueryRunner runner = SQLUtil.initQueryRunner(SAMPLES_DB, false);
            runner.update("INSERT INTO Samples (sample, time) VALUES (?, ?)",
                    sample.toByteArray(), System.currentTimeMillis());

            exchange.sendResponseHeaders(200, -1);
        }
    }
}
