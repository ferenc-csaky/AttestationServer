package app.attestation.server.dto;

public class LoginDTO extends PasswordDTO {
    private long userId;

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }
}
