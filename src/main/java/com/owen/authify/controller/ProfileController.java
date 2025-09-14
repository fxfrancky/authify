package com.owen.authify.controller;

import com.owen.authify.io.ProfileRequest;
import com.owen.authify.io.ProfileResponse;
import com.owen.authify.service.EmailService;
import com.owen.authify.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
//@RequestMapping("/api/v1.0")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;
    private final EmailService emailService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse register(@Valid @RequestBody ProfileRequest profileRequest) {
        ProfileResponse profileResponse = profileService.createProfile(profileRequest);
        //send welcome email
        emailService.sendWelcomeEmail(profileResponse.getEmail(), profileResponse.getName());
        return profileResponse;
    }

    @GetMapping("/profile")
    public ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication?.name") String email) {
        return profileService.getProfile(email);
    }
}
