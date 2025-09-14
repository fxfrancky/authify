package com.owen.authify.io;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProfileRequest {

    @NotBlank(message = "Name should be not empty")
    private String name;
    @Email(message = "Enter valid email address")
    @NotNull(message = "Email should be not empty")
    private String email;
    @Size(min = 6, message = "Password must be atleast 6 characters long" )
    private String password;
}
