package com.balcia.auth;

import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;

public class LoginResponse {
    public String accessToken;
    public Integer expiresIn;
    public String tokenType;
    public String refereshToken;
    public String idToken;

    public LoginResponse() {
    }

    public LoginResponse(AuthenticationResultType authenticationResult) {
        accessToken = authenticationResult.accessToken();
        expiresIn = authenticationResult.expiresIn();
        tokenType = authenticationResult.tokenType();
        refereshToken = authenticationResult.refreshToken();
        idToken = authenticationResult.idToken();
    }
}
