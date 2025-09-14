package com.owen.authify.entity;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "utilisateur")
public class UserEntity {

    @Id
    private String id;
    @Field("userId")
    private String userId;
    @Field("name")
    private String name;
    @Field("email")
    private String email;
    @Field("password")
    private String password;
    @Field("verifyOtp")
    private String verifyOtp;
    @Field("isAccountVerified")
    private Boolean isAccountVerified;
    @Field("verifyOptExpireAt")
    private Long verifyOptExpireAt;
    @Field("resetOpt")
    private String resetOpt;
    @Field("resetOptExpireAt")
    private Long resetOptExpireAt;

    @CreatedDate
    @Field("createdAt")
    private Date createdAt;
    @LastModifiedDate
    @Field("updatedAt")
    private Date updatedAt;
}
