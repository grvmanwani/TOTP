package com.gaurav.otpservice;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class TimeBasedOneTimePasswordUtil {

    /** default time-step which is part of the spec, 30 seconds is default */
    public static final int DEFAULT_TIME_STEP_SECONDS = 600;
    /** set to the number of digits to control 0 prefix, set to 0 for no prefix */
    private static int NUM_DIGITS_OUTPUT = 6;

    private static String blockOfZeros;

    private static void initializeBlockOfZeros(int numberOfDigits){
        char[] chars = new char[numberOfDigits];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = '0';
        }
        blockOfZeros = new String(chars);
    }

    /**
     * Generate and return a 16-character secret key in base32 format (A-Z2-7) using {@link SecureRandom}. Could be used
     * to generate the QR image to be shared with the user. Other lengths should use {@link #generateBase32Secret(int)}.
     */
    public static String generateBase32Secret() {
        return generateBase32Secret(16);
    }

    /**
     * Similar to {@link #generateBase32Secret()} but specifies a character length.
     */
    public static String generateBase32Secret(int length) {
        StringBuilder sb = new StringBuilder(length);
        Random random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int val = random.nextInt(32);
            if (val < 26) {
                sb.append((char) ('A' + val));
            } else {
                sb.append((char) ('2' + (val - 26)));
            }
        }
        return sb.toString();
    }

    /**
     * Validate a given secret-number using the secret base-32 string. This allows you to set a window in milliseconds
     * to account for people being close to the end of the time-step. For example, if windowMillis is 10000 then this
     * method will check the authNumber against the generated number from 10 seconds before now through 10 seconds after
     * now.
     *
     * <p>
     * WARNING: This requires a system clock that is in sync with the world.
     * </p>
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
     * @param authNumber
     *            Time based number provided by the user from their authenticator application.
     * @param windowMillis
     *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
     *            the current time to account for clock variance. Set to 0 for no window.
     * @return True if the authNumber matched the calculated number within the specified window.
     */
    public static boolean validateCurrentNumber(String base32Secret, int authNumber, int windowMillis, int expiryTimeInMinutes)
            throws GeneralSecurityException {
        if(0==expiryTimeInMinutes) {
            return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(),
                    DEFAULT_TIME_STEP_SECONDS);
        }else{
            return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(),
                    expiryTimeInMinutes);
        }
    }

    /**
     * Similar to {@link #validateCurrentNumber(String, int, int)} except exposes other parameters. Mostly for testing.
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
     * @param authNumber
     *            Time based number provided by the user from their authenticator application.
     * @param expiryTimeInMinutes
     *            Time step in seconds. The default value is 600 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
     * @return True if the authNumber matched the calculated number within the specified window.
     */
    public static boolean validateCurrentNumber(String base32Secret, int authNumber, int expiryTimeInMinutes)
            throws GeneralSecurityException {
        return validateCurrentNumber(base32Secret, authNumber, 0, System.currentTimeMillis(),
                expiryTimeInMinutes*60);
    }

    /**
     * Similar to {@link #validateCurrentNumber(String, int, int)} except exposes other parameters. Mostly for testing.
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
     * @param authNumber
     *            Time based number provided by the user from their authenticator application.
     * @param windowMillis
     *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
     *            the current time to account for clock variance. Set to 0 for no window.
     * @param timeMillis
     *            Time in milliseconds.
     * @param timeStepSeconds
     *            Time step in seconds. The default value is 600 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
     * @return True if the authNumber matched the calculated number within the specified window.
     */
    public static boolean validateCurrentNumber(String base32Secret, int authNumber, int windowMillis, long timeMillis,
                                                int timeStepSeconds) throws GeneralSecurityException {
        long fromTimeMillis = timeMillis;
        long toTimeMillis = timeMillis;
        if (windowMillis > 0) {
            fromTimeMillis -= windowMillis;
            toTimeMillis += windowMillis;
        }
        long timeStepMillis = timeStepSeconds * 1000;
        for (long millis = fromTimeMillis; millis <= toTimeMillis; millis += timeStepMillis) {
            int generatedNumber = generateNumber(base32Secret, millis, timeStepSeconds);
            if (generatedNumber == authNumber) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the current number to be checked. This can be compared against user input.
     *
     * <p>
     * WARNING: This requires a system clock that is in sync with the world.
     * </p>
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was shared with the user.
     * @return A number as a string with possible leading zeros which should match the user's authenticator application
     *         output.
     */
    public static String generateOTPString(String base32Secret) throws GeneralSecurityException {
        return generateNumberString(base32Secret,0, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS);
    }

    /**
     * Similar to {@link #generateOTPString(String)} except exposes other parameters. Mostly for testing.
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
     *
     * @Param numberOfDigits number of digits of OTP
     * @param expiryTimeInMinutes
     *            Time step in minutes. The default value is 600 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
     * @return A number as a string with possible leading zeros which should match the user's authenticator application
     *         output.
     */
    public static String generateOTPString(String base32Secret,int numberOfDigits, int expiryTimeInMinutes) throws GeneralSecurityException {
        return generateNumberString(base32Secret,numberOfDigits, System.currentTimeMillis(), expiryTimeInMinutes*60);
    }

    /**
     * Similar to {@link #generateOTPString(String)} except exposes other parameters. Mostly for testing.
     *
     * @param base32Secret
     *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
     * @param timeMillis
     *            Time in milliseconds.
     * @param timeStepSeconds
     *            Time step in seconds. The default value is 30 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
     * @return A number as a string with possible leading zeros which should match the user's authenticator application
     *         output.
     */
    private static String generateNumberString(String base32Secret,int numberOFOutputDigits, long timeMillis, int timeStepSeconds)
            throws GeneralSecurityException {
        int number = generateNumber(base32Secret, timeMillis, timeStepSeconds);
        if(numberOFOutputDigits==0) {
            initializeBlockOfZeros(NUM_DIGITS_OUTPUT);
            return zeroPrepend(number, NUM_DIGITS_OUTPUT);
        }else{
            initializeBlockOfZeros(numberOFOutputDigits);
            return zeroPrepend(number, numberOFOutputDigits);
        }
    }

    /**
     * Similar to {@link #generateOTPString(String)} but this returns a int instead of a string.
     *
     * @return A number which should match the user's authenticator application output.
     */
    public static int generateCurrentNumber(String base32Secret) throws GeneralSecurityException {
        return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS);
    }

    /**
     * Similar to {@link #generateNumberString(String,int, long, int)} but this returns a int instead of a string.
     *
     * @return A number which should match the user's authenticator application output.
     */
    public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds)
            throws GeneralSecurityException {

        byte[] key = decodeBase32(base32Secret);

        byte[] data = new byte[8];
        long value = timeMillis / 1000 / timeStepSeconds;
        for (int i = 7; value > 0; i--) {
            data[i] = (byte) (value & 0xFF);
            value >>= 8;
        }

        // encrypt the data with the key and return the SHA1 of it in hex
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        // if this is expensive, could put in a thread-local
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        // take the 4 least significant bits from the encrypted string as an offset
        int offset = hash[hash.length - 1] & 0xF;

        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = offset; i < offset + 4; ++i) {
            truncatedHash <<= 8;
            // get the 4 bytes at the offset
            truncatedHash |= (hash[i] & 0xFF);
        }
        // cut off the top bit
        truncatedHash &= 0x7FFFFFFF;

        // the token is then the last 6 digits in the number
        truncatedHash %= 1000000;
        // this is only 6 digits so we can safely case it
        return (int) truncatedHash;
    }

    /**
     * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
     */
    static String zeroPrepend(int num, int digits) {
        String numStr = Integer.toString(num);
        if (numStr.length() >= digits) {
            return numStr;
        } else {
            StringBuilder sb = new StringBuilder(digits);
            int zeroCount = digits - numStr.length();
            sb.append(blockOfZeros, 0, zeroCount);
            sb.append(numStr);
            return sb.toString();
        }
    }

    /**
     * Decode base-32 method. I didn't want to add a dependency to Apache Codec just for this decode method. Exposed for
     * testing.
     */
    static byte[] decodeBase32(String str) {
        // each base-32 character encodes 5 bits
        int numBytes = ((str.length() * 5) + 7) / 8;
        byte[] result = new byte[numBytes];
        int resultIndex = 0;
        int which = 0;
        int working = 0;
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            int val;
            if (ch >= 'a' && ch <= 'z') {
                val = ch - 'a';
            } else if (ch >= 'A' && ch <= 'Z') {
                val = ch - 'A';
            } else if (ch >= '2' && ch <= '7') {
                val = 26 + (ch - '2');
            } else if (ch == '=') {
                // special case
                which = 0;
                break;
            } else {
                throw new IllegalArgumentException("Invalid base-32 character: " + ch);
            }
            /*
             * There are probably better ways to do this but this seemed the most straightforward.
             */
            switch (which) {
                case 0:
                    // all 5 bits is top 5 bits
                    working = (val & 0x1F) << 3;
                    which = 1;
                    break;
                case 1:
                    // top 3 bits is lower 3 bits
                    working |= (val & 0x1C) >> 2;
                    result[resultIndex++] = (byte) working;
                    // lower 2 bits is upper 2 bits
                    working = (val & 0x03) << 6;
                    which = 2;
                    break;
                case 2:
                    // all 5 bits is mid 5 bits
                    working |= (val & 0x1F) << 1;
                    which = 3;
                    break;
                case 3:
                    // top 1 bit is lowest 1 bit
                    working |= (val & 0x10) >> 4;
                    result[resultIndex++] = (byte) working;
                    // lower 4 bits is top 4 bits
                    working = (val & 0x0F) << 4;
                    which = 4;
                    break;
                case 4:
                    // top 4 bits is lowest 4 bits
                    working |= (val & 0x1E) >> 1;
                    result[resultIndex++] = (byte) working;
                    // lower 1 bit is top 1 bit
                    working = (val & 0x01) << 7;
                    which = 5;
                    break;
                case 5:
                    // all 5 bits is mid 5 bits
                    working |= (val & 0x1F) << 2;
                    which = 6;
                    break;
                case 6:
                    // top 2 bits is lowest 2 bits
                    working |= (val & 0x18) >> 3;
                    result[resultIndex++] = (byte) working;
                    // lower 3 bits of byte 6 is top 3 bits
                    working = (val & 0x07) << 5;
                    which = 7;
                    break;
                case 7:
                    // all 5 bits is lower 5 bits
                    working |= (val & 0x1F);
                    result[resultIndex++] = (byte) working;
                    which = 0;
                    break;
            }
        }
        if (which != 0) {
            result[resultIndex++] = (byte) working;
        }
        if (resultIndex != result.length) {
            result = Arrays.copyOf(result, resultIndex);
        }
        return result;
    }
}
