package app.attestation.server.dto;

public class AccountAlertDTO {
    private long userId;
    private int alertDelay;

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public int getAlertDelay() {
        return alertDelay;
    }

    public void setAlertDelay(int alertDelay) {
        this.alertDelay = alertDelay;
    }
}
