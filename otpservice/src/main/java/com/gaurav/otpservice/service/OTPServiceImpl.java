package com.gaurav.otpservice.service;

import com.gaurav.otpservice.OTPDto;
import com.gaurav.otpservice.TimeBasedOneTimePasswordUtil;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;


@Service
public class OTPServiceImpl implements OTPService {
    @Override
    public OTPDto generateOTP(int numberOfDigits, int expiryTimeInMinutes) {
        String referenceKey = TimeBasedOneTimePasswordUtil.generateBase32Secret();
        String otp ="";
        try {
            otp = TimeBasedOneTimePasswordUtil.generateOTPString(referenceKey,numberOfDigits,expiryTimeInMinutes);
        } catch (GeneralSecurityException ge) {
            System.out.println(ge);
        }
        return new OTPDto(otp,referenceKey);
    }

    @Override
    public OTPDto validateOTP(int otpValue, String referenceKey, int expiryTimeInMinutes) {
        boolean returnValue=false;
        try {
            returnValue = TimeBasedOneTimePasswordUtil.validateCurrentNumber(referenceKey, otpValue,expiryTimeInMinutes);
        } catch (Exception e){
            System.out.println(e);
        }
        return new OTPDto(returnValue);
    }
}
