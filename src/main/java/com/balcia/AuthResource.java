package com.balcia;

import com.balcia.auth.GlobalConfiguration;
import com.balcia.auth.HashResult;
import com.balcia.auth.RegisterRequest;
import com.balcia.auth.cognito.CognitoService;
import com.balcia.auth.smartid.SmartIdService;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Path("/auth")
public class AuthResource {

    @Inject
    GlobalConfiguration globalConfiguration;

    @Inject
    SmartIdService smartIdService;
    @Inject
    CognitoService cognitoService;

    @GET
    @Path("/hash")
    public HashResult hash() {
        return smartIdService.hash();
    }

    @POST
    @Path("/register")
    public AdminGetUserResponse register(RegisterRequest registerRequest) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

        System.setProperty("javax.net.ssl.trustStore", getClass().getResource(globalConfiguration.storeFile()).getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", globalConfiguration.storePassword());

        smartIdService.register(registerRequest);
        return cognitoService.register(registerRequest);
    }
}
