package com.balcia.auth.cognito;

import io.smallrye.config.ConfigMapping;

import java.util.Optional;

@ConfigMapping(prefix = "cognito")
interface CognitoConfiguration {
    String region();
    String accessKeyId();
    String secretAccessKey();
    String userPoolId();
    String userPoolClientId();
    Optional<String> userPoolClientSecret();
}
