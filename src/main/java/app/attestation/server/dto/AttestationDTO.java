package app.attestation.server.dto;

public class AttestationDTO {
    private long time;
    private int strong;
    private String teeEnforced;
    private String osEnforced;

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    public int getStrong() {
        return strong;
    }

    public void setStrong(int strong) {
        this.strong = strong;
    }

    public String getTeeEnforced() {
        return teeEnforced;
    }

    public void setTeeEnforced(String teeEnforced) {
        this.teeEnforced = teeEnforced;
    }

    public String getOsEnforced() {
        return osEnforced;
    }

    public void setOsEnforced(String osEnforced) {
        this.osEnforced = osEnforced;
    }
}
