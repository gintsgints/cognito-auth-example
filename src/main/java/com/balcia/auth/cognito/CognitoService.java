package com.balcia.auth.cognito;

import com.balcia.auth.*;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class CognitoService {

    CognitoConfiguration cognitoConfiguration;

    private final CognitoIdentityProviderClient identityProviderClient;

    @Inject
    public CognitoService(CognitoConfiguration cognitoConfiguration) {
        identityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.of(cognitoConfiguration.region()))
                .credentialsProvider(StaticCredentialsProvider
                        .create(AwsBasicCredentials.create(cognitoConfiguration.accessKeyId(), cognitoConfiguration.secretAccessKey())))
                .build();
        this.cognitoConfiguration = cognitoConfiguration;
    }

    public String requestConfirmEmail(ResendRequest resendRequest) {
        ResendConfirmationCodeRequest resendConfirmationCodeRequest = ResendConfirmationCodeRequest.builder()
                .clientId(cognitoConfiguration.userPoolClientId())
                .username(resendRequest.email)
                .build();
        identityProviderClient.resendConfirmationCode(resendConfirmationCodeRequest);
        return "OK";
    }

    public ConfirmSignUpResponse confirm(ConfirmRequest confirmRequest) {
        ConfirmSignUpRequest confirmSignUpRequest = ConfirmSignUpRequest.builder()
                .clientId(cognitoConfiguration.userPoolClientId())
                .confirmationCode(confirmRequest.code)
                .username(confirmRequest.email)
                .build();

        return identityProviderClient.confirmSignUp(confirmSignUpRequest);
    }

    public LoginResponse referesh(RefreshRequest refreshRequest) {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("REFRESH_TOKEN", refreshRequest.refreshToken);

        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                .clientId(cognitoConfiguration.userPoolClientId())
                .authParameters(authParameters)
                .build();

        InitiateAuthResponse initiateAuthResponse = identityProviderClient.initiateAuth(initiateAuthRequest);
        LoginResponse loginResponse = new LoginResponse(initiateAuthResponse.authenticationResult());

        return loginResponse;
    }

    public LoginResponse login(LoginRequest loginRequest) {

        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("USERNAME", loginRequest.userName);
        authParameters.put("PASSWORD", loginRequest.password);

        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(cognitoConfiguration.userPoolClientId())
                .authParameters(authParameters)
                .build();

        InitiateAuthResponse initiateAuthResponse = identityProviderClient.initiateAuth(initiateAuthRequest);
        LoginResponse loginResponse = new LoginResponse(initiateAuthResponse.authenticationResult());

        return loginResponse;
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

        userAttrsList.add(AttributeType.builder()
                .name("custom:base64_hash")
                .value(registerRequest.hashInBase64)
                .build());

        userAttrsList.add(AttributeType.builder()
                .name("custom:hash_type")
                .value(registerRequest.hashType)
                .build());

        SignUpRequest request = SignUpRequest.builder()
                .clientId(cognitoConfiguration.userPoolClientId())
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
}
