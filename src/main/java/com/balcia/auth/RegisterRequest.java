package com.balcia.auth;

public class RegisterRequest {
    public String email;
    public String password;
    public String rc;
    public String hashInBase64;
    public String hashType;

    public RegisterRequest() {
    }
}
