package com.balcia;

import com.balcia.auth.*;
import com.balcia.auth.cognito.CognitoService;
import com.balcia.auth.smartid.SmartIdService;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

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
    @Path("/confirm")
    public Response confirm(ConfirmRequest confirmRequest) {
        return Response.ok(cognitoService.confirm(confirmRequest)).build();
    }

    @POST
    @Path("/refresh")
    public Response refresh(RefreshRequest refreshRequest) {
        return Response.ok(cognitoService.referesh(refreshRequest)).build();
    }

    @POST
    @Path("/login")
    public Response login(LoginRequest loginRequest) {
        LoginResponse loginResponse = cognitoService.login(loginRequest);
        return Response.ok(loginResponse).build();
    }

    @POST
    @Path("/register")
    public Response register(RegisterRequest registerRequest) {

        System.setProperty("javax.net.ssl.trustStore", getClass().getResource(globalConfiguration.storeFile()).getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", globalConfiguration.storePassword());

        smartIdService.register(registerRequest);
        return Response.ok(cognitoService.register(registerRequest)).build();
    }
}
