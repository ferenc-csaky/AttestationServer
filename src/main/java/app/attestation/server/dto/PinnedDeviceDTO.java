package app.attestation.server.dto;

public class PinnedDeviceDTO {
    private long userId;
    private byte[] pinnedCertificate0;
    private byte[] pinnedCertificate1;
    private byte[] pinnedCertificate2;
    private byte[] pinnedVerifiedBootKey;
    private int pinnedOsVersion;
    private int pinnedOsPatchLevel;
    private int pinnedVendorPatchLevel;
    private int pinnedBootPatchLevel;
    private int pinnedAppVersion;
    private int pinnedSecurityLevel;

    public byte[][] getPinnedCertificates() {
        return new byte[][]{pinnedCertificate0, pinnedCertificate1, pinnedCertificate2};
    }

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public byte[] getPinnedCertificate0() {
        return pinnedCertificate0;
    }

    public void setPinnedCertificate0(byte[] pinnedCertificate0) {
        this.pinnedCertificate0 = pinnedCertificate0;
    }

    public byte[] getPinnedCertificate1() {
        return pinnedCertificate1;
    }

    public void setPinnedCertificate1(byte[] pinnedCertificate1) {
        this.pinnedCertificate1 = pinnedCertificate1;
    }

    public byte[] getPinnedCertificate2() {
        return pinnedCertificate2;
    }

    public void setPinnedCertificate2(byte[] pinnedCertificate2) {
        this.pinnedCertificate2 = pinnedCertificate2;
    }

    public byte[] getPinnedVerifiedBootKey() {
        return pinnedVerifiedBootKey;
    }

    public void setPinnedVerifiedBootKey(byte[] pinnedVerifiedBootKey) {
        this.pinnedVerifiedBootKey = pinnedVerifiedBootKey;
    }

    public int getPinnedOsVersion() {
        return pinnedOsVersion;
    }

    public void setPinnedOsVersion(int pinnedOsVersion) {
        this.pinnedOsVersion = pinnedOsVersion;
    }

    public int getPinnedOsPatchLevel() {
        return pinnedOsPatchLevel;
    }

    public void setPinnedOsPatchLevel(int pinnedOsPatchLevel) {
        this.pinnedOsPatchLevel = pinnedOsPatchLevel;
    }

    public int getPinnedVendorPatchLevel() {
        return pinnedVendorPatchLevel;
    }

    public void setPinnedVendorPatchLevel(int pinnedVendorPatchLevel) {
        this.pinnedVendorPatchLevel = pinnedVendorPatchLevel;
    }

    public int getPinnedBootPatchLevel() {
        return pinnedBootPatchLevel;
    }

    public void setPinnedBootPatchLevel(int pinnedBootPatchLevel) {
        this.pinnedBootPatchLevel = pinnedBootPatchLevel;
    }

    public int getPinnedAppVersion() {
        return pinnedAppVersion;
    }

    public void setPinnedAppVersion(int pinnedAppVersion) {
        this.pinnedAppVersion = pinnedAppVersion;
    }

    public int getPinnedSecurityLevel() {
        return pinnedSecurityLevel;
    }

    public void setPinnedSecurityLevel(int pinnedSecurityLevel) {
        this.pinnedSecurityLevel = pinnedSecurityLevel;
    }
}
