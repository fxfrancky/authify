package com.owen.authify.service;

import com.owen.authify.entity.UserEntity;
import com.owen.authify.io.ProfileRequest;
import com.owen.authify.io.ProfileResponse;
import com.owen.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;

    // To encode a password
    private final PasswordEncoder passwordEncoder;

    private final EmailService emailService;


    @Override
    public ProfileResponse createProfile(ProfileRequest profileRequest) {
        UserEntity newProfile = convertToUserEntity(profileRequest);

        if(!userRepository.existsByEmail(newProfile.getEmail())) {
            newProfile = userRepository.save(newProfile);
            return convertToProfileResponse(newProfile);
        }

        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }

    @Override
    public ProfileResponse getProfile(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: "+email));
        return convertToProfileResponse(existingUser);
    }


    private UserEntity convertToUserEntity(ProfileRequest profileRequest) {
        return UserEntity.builder()
                .email(profileRequest.getEmail())
                .userId(UUID.randomUUID().toString())
                .name(profileRequest.getName())
                .password(passwordEncoder.encode(profileRequest.getPassword()))
                .isAccountVerified(false)
                .resetOptExpireAt(0L)
                .verifyOtp(null)
                .verifyOptExpireAt(0L)
                .resetOpt(null)
                .build();
    }

    private ProfileResponse convertToProfileResponse(UserEntity newProfile) {

        return ProfileResponse.builder()
                .name(newProfile.getName())
                .email(newProfile.getEmail())
                .userId(newProfile.getUserId())
                .isAccountVerified(newProfile.getIsAccountVerified())
                .build();
    }



    @Override
    public void sendResetOtpEmail(String email) {

        UserEntity existingUserEntity = userRepository.findByEmail(email)
                                            .orElseThrow(() -> new UsernameNotFoundException("User not found: "+email));

        // Generate 6 digits otp
        String otpCode = String.valueOf(ThreadLocalRandom.current().nextLong(100000,1000000));

        // calculate expiry time (current time + 15 min in milliseconds
        long expiryTime = System.currentTimeMillis() + (15 * 60 * 1000);

        // update the profile / user
        existingUserEntity.setResetOpt(otpCode);
        existingUserEntity.setResetOptExpireAt(expiryTime);

        // Save into the database
        userRepository.save(existingUserEntity);

        try {
            emailService.sendResetOtpEmail(existingUserEntity.getEmail(), otpCode);
        } catch (Exception e) {
            throw new RuntimeException("Unable to send reset OTP email");
        }
    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
       UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));

        if(existingUser.getResetOpt()==  null || !existingUser.getResetOpt().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }
        if (existingUser.getResetOptExpireAt() <= System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setResetOpt(null);
        existingUser.setResetOptExpireAt(0L);

        userRepository.save(existingUser);
    }

    @Override
    public void sendOtp(String email) {

        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: "+email));

        if (existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()){
            return;
        }

        // generate OTP
        // Generate 6 digits otp
        String otpCode = String.valueOf(ThreadLocalRandom.current().nextLong(100000,1000000));

        // calculate expiry time (current time + 24 hours in milliseconds
        long expiryTime = System.currentTimeMillis() + (24 * 60 * 60 * 1000);

        // Update the user entity
        existingUser.setVerifyOtp(otpCode);
        existingUser.setVerifyOptExpireAt(expiryTime);

        // save to database
        userRepository.save(existingUser);
    }

    @Override
    public void verifyOtp(String email, String otp) {

    }


    @Override
    public String getLoggedInUserId(String email) {
       UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: "+email));
        return existingUser.getUserId();
    }

}
