package app.attestation.server.dto;

public class SessionDTO {
    private String username;
    private long userId;
    private long expiryTime;
    private int verifyInterval;
    private int alertDelay;
    private byte[] subscribeKey;
    private byte[] cookieToken;
    private byte[] requestToken;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    public int getVerifyInterval() {
        return verifyInterval;
    }

    public void setVerifyInterval(int verifyInterval) {
        this.verifyInterval = verifyInterval;
    }

    public int getAlertDelay() {
        return alertDelay;
    }

    public void setAlertDelay(int alertDelay) {
        this.alertDelay = alertDelay;
    }

    public byte[] getSubscribeKey() {
        return subscribeKey;
    }

    public void setSubscribeKey(byte[] subscribeKey) {
        this.subscribeKey = subscribeKey;
    }

    public byte[] getCookieToken() {
        return cookieToken;
    }

    public void setCookieToken(byte[] cookieToken) {
        this.cookieToken = cookieToken;
    }

    public byte[] getRequestToken() {
        return requestToken;
    }

    public void setRequestToken(byte[] requestToken) {
        this.requestToken = requestToken;
    }
}
