package com.gaurav.otpservice.controller;

import com.gaurav.otpservice.OTPDto;
import com.gaurav.otpservice.service.OTPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
public class OTPController {

    @Autowired
    private OTPService otpService;

    @GetMapping("/generate-otp/{no_of_digits}/{expiry_time_minutes}")
    public OTPDto generateOTP(@PathVariable("no_of_digits") int numberOfDigits
    ,@PathVariable("expiry_time_minutes") int expiryTimeInMinutes){
        return otpService.generateOTP(numberOfDigits,expiryTimeInMinutes);
    }

    @PostMapping("/validate-otp")
    public OTPDto validateOTP(@RequestBody OTPDto otpDto){
        return otpService.validateOTP(Integer.parseInt(otpDto.getOtpValue()),otpDto.getReferenceId(), otpDto.getExpiryTimeInMinutes());
    }
}
