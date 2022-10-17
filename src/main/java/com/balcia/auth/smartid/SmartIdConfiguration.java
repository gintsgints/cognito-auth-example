package com.balcia.auth.smartid;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "smart-id")
interface SmartIdConfiguration {
    String relyingPartyUUID();

    String relyingPartyName();

    String hostUrl();
}
