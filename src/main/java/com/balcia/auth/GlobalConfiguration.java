package com.balcia.auth;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "global")
public interface GlobalConfiguration {
    String storeFile();

    String storePassword();
}
