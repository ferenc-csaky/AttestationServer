package app.attestation.server.dto;

public class DeviceDTO {
    private byte[] fingerprint;
    private byte[] pinnedCertificate0;
    private byte[] pinnedCertificate1;
    private byte[] pinnedCertificate2;
    private String verifiedBootKeyVal;
    private String verifiedBootHashVal;
    private Integer pinnedOsVersion;
    private Integer pinnedOsPatchLevel;
    private Integer pinnedVendorPatchLevel;
    private Integer pinnedBootPatchLevel;
    private Integer pinnedAppVersion;
    private Integer pinnedSecurityLevel;
    private Integer userProfileSecure;
    private Integer enrolledFingerprints;
    private Integer accessibility;
    private Integer deviceAdmin;
    private Integer adbEnabled;
    private Integer addUsersWhenLocked;
    private Integer denyNewUsb;
    private Integer oemUnlockAllowed;
    private Integer systemUser;
    private long verifiedTimeFirst;
    private long verifiedTimeLast;

    public byte[] getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
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

    public String getVerifiedBootKeyVal() {
        return verifiedBootKeyVal;
    }

    public void setVerifiedBootKeyVal(String verifiedBootKeyVal) {
        this.verifiedBootKeyVal = verifiedBootKeyVal;
    }

    public String getVerifiedBootHashVal() {
        return verifiedBootHashVal;
    }

    public void setVerifiedBootHashVal(String verifiedBootHashVal) {
        this.verifiedBootHashVal = verifiedBootHashVal;
    }

    public Integer getPinnedOsVersion() {
        return pinnedOsVersion;
    }

    public void setPinnedOsVersion(Integer pinnedOsVersion) {
        this.pinnedOsVersion = pinnedOsVersion;
    }

    public Integer getPinnedOsPatchLevel() {
        return pinnedOsPatchLevel;
    }

    public void setPinnedOsPatchLevel(Integer pinnedOsPatchLevel) {
        this.pinnedOsPatchLevel = pinnedOsPatchLevel;
    }

    public Integer getPinnedVendorPatchLevel() {
        return pinnedVendorPatchLevel;
    }

    public void setPinnedVendorPatchLevel(Integer pinnedVendorPatchLevel) {
        this.pinnedVendorPatchLevel = pinnedVendorPatchLevel;
    }

    public Integer getPinnedBootPatchLevel() {
        return pinnedBootPatchLevel;
    }

    public void setPinnedBootPatchLevel(Integer pinnedBootPatchLevel) {
        this.pinnedBootPatchLevel = pinnedBootPatchLevel;
    }

    public Integer getPinnedAppVersion() {
        return pinnedAppVersion;
    }

    public void setPinnedAppVersion(Integer pinnedAppVersion) {
        this.pinnedAppVersion = pinnedAppVersion;
    }

    public Integer getPinnedSecurityLevel() {
        return pinnedSecurityLevel;
    }

    public void setPinnedSecurityLevel(Integer pinnedSecurityLevel) {
        this.pinnedSecurityLevel = pinnedSecurityLevel;
    }

    public Integer getUserProfileSecure() {
        return userProfileSecure;
    }

    public void setUserProfileSecure(Integer userProfileSecure) {
        this.userProfileSecure = userProfileSecure;
    }

    public Integer getEnrolledFingerprints() {
        return enrolledFingerprints;
    }

    public void setEnrolledFingerprints(Integer enrolledFingerprints) {
        this.enrolledFingerprints = enrolledFingerprints;
    }

    public Integer getAccessibility() {
        return accessibility;
    }

    public void setAccessibility(Integer accessibility) {
        this.accessibility = accessibility;
    }

    public Integer getDeviceAdmin() {
        return deviceAdmin;
    }

    public void setDeviceAdmin(Integer deviceAdmin) {
        this.deviceAdmin = deviceAdmin;
    }

    public Integer getAdbEnabled() {
        return adbEnabled;
    }

    public void setAdbEnabled(Integer adbEnabled) {
        this.adbEnabled = adbEnabled;
    }

    public Integer getAddUsersWhenLocked() {
        return addUsersWhenLocked;
    }

    public void setAddUsersWhenLocked(Integer addUsersWhenLocked) {
        this.addUsersWhenLocked = addUsersWhenLocked;
    }

    public Integer getDenyNewUsb() {
        return denyNewUsb;
    }

    public void setDenyNewUsb(Integer denyNewUsb) {
        this.denyNewUsb = denyNewUsb;
    }

    public Integer getOemUnlockAllowed() {
        return oemUnlockAllowed;
    }

    public void setOemUnlockAllowed(Integer oemUnlockAllowed) {
        this.oemUnlockAllowed = oemUnlockAllowed;
    }

    public Integer getSystemUser() {
        return systemUser;
    }

    public void setSystemUser(Integer systemUser) {
        this.systemUser = systemUser;
    }

    public long getVerifiedTimeFirst() {
        return verifiedTimeFirst;
    }

    public void setVerifiedTimeFirst(long verifiedTimeFirst) {
        this.verifiedTimeFirst = verifiedTimeFirst;
    }

    public long getVerifiedTimeLast() {
        return verifiedTimeLast;
    }

    public void setVerifiedTimeLast(long verifiedTimeLast) {
        this.verifiedTimeLast = verifiedTimeLast;
    }
}
