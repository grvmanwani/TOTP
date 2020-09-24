package com.gaurav.otpservice;


public class OTPDto {

    private String otpValue;
    private String referenceId;

    private boolean validated;
    private int expiryTimeInMinutes;

    public OTPDto() {
    }

    public OTPDto(String otpValue, String referenceId) {
        this.otpValue = otpValue;
        this.referenceId = referenceId;
    }

    public int getExpiryTimeInMinutes() {
        return expiryTimeInMinutes;
    }

    public void setExpiryTimeInMinutes(int expiryTimeInMinutes) {
        this.expiryTimeInMinutes = expiryTimeInMinutes;
    }

    public OTPDto(boolean validated) {
        this.validated = validated;
    }

    public String getOtpValue() {
        return otpValue;
    }

    public void setOtpValue(String otpValue) {
        this.otpValue = otpValue;
    }

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    public boolean isValidated() {
        return validated;
    }

    public void setValidated(boolean validated) {
        this.validated = validated;
    }
}
