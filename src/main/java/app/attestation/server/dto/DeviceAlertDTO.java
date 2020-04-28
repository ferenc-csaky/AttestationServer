package app.attestation.server.dto;

public class DeviceAlertDTO {
    private byte[] fingerprint;
    private long expiredTimeLast;

    public byte[] getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
    }

    public long getExpiredTimeLast() {
        return expiredTimeLast;
    }

    public void setExpiredTimeLast(long expiredTimeLast) {
        this.expiredTimeLast = expiredTimeLast;
    }
}
