package com.gaurav.otpservice.service;

import com.gaurav.otpservice.OTPDto;
import org.springframework.stereotype.Service;


public interface OTPService {
    OTPDto generateOTP(int numberOfDigits, int expiryTimeInMinutes);

    OTPDto validateOTP(int otpValue, String referenceKey, int expiryTimeInMinutes);
}
