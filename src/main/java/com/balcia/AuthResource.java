package com.balcia;

import com.balcia.auth.RegisterRequest;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

@Path("/auth")
public class AuthResource {

    @POST
    @Path("/register")
    public String register(RegisterRequest fruit) {
        return "Register response for PK::" + fruit.rc;
    }
}
