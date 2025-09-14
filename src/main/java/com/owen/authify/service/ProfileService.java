package com.owen.authify.service;

import com.owen.authify.io.ProfileRequest;
import com.owen.authify.io.ProfileResponse;

public interface ProfileService {

    ProfileResponse createProfile(ProfileRequest profileRequest);

    ProfileResponse getProfile(String email);

    void sendResetOtpEmail(String email);

    void resetPassword(String email, String otp, String newPassword);

    void sendOtp(String email);;

    void verifyOtp(String email, String otp);

    String getLoggedInUserId(String email);
}
