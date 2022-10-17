package com.balcia.auth.cognito;

import com.balcia.auth.RegisterRequest;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@ApplicationScoped
public class CognitoService {

    CognitoConfiguration cognitoConfiguration;

    private final CognitoIdentityProviderClient identityProviderClient;

    @Inject
    public CognitoService(CognitoConfiguration cognitoConfiguration) {
        identityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.EU_CENTRAL_1)
                .credentialsProvider(StaticCredentialsProvider
                        .create(AwsBasicCredentials.create(cognitoConfiguration.accessKeyId(), cognitoConfiguration.secretAccessKey())))
                .build();
        this.cognitoConfiguration = cognitoConfiguration;
    }

    public AdminGetUserResponse register(RegisterRequest registerRequest) {
        List<AttributeType> userAttrsList = new ArrayList<>();

        userAttrsList.add(AttributeType.builder()
                .name("email")
                .value(registerRequest.email)
                .build());

        userAttrsList.add(AttributeType.builder()
                .name("custom:registry_code")
                .value(registerRequest.rc)
                .build());

        SignUpRequest request = SignUpRequest.builder()
                .clientId(cognitoConfiguration.userPoolClientId())
                .secretHash(calculateSecretHash(cognitoConfiguration.userPoolClientId(), cognitoConfiguration.userPoolClientSecret(), registerRequest.email))
                .username(registerRequest.email)
                .password(registerRequest.password)
                .userAttributes(userAttrsList)
                .build();

        identityProviderClient.signUp(request);

        return identityProviderClient.adminGetUser(AdminGetUserRequest.builder()
                .userPoolId(cognitoConfiguration.userPoolId())
                .username(registerRequest.email)
                .build());
    }

    private String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }
}
