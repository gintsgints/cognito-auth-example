package com.balcia.auth.cognito;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "cognito")
interface CognitoConfiguration {
    String accessKeyId();
    String secretAccessKey();
    String userPoolId();
    String userPoolClientId();
    String userPoolClientSecret();
}
