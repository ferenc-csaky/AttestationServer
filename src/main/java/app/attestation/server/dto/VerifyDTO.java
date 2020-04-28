package app.attestation.server.dto;

public class VerifyDTO {
    private byte[] subscribeKey;
    private int verifyInterval;

    public byte[] getSubscribeKey() {
        return subscribeKey;
    }

    public void setSubscribeKey(byte[] subscribeKey) {
        this.subscribeKey = subscribeKey;
    }

    public int getVerifyInterval() {
        return verifyInterval;
    }

    public void setVerifyInterval(int verifyInterval) {
        this.verifyInterval = verifyInterval;
    }
}
