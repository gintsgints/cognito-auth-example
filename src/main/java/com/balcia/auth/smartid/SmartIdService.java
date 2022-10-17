package com.balcia.auth.smartid;

import com.balcia.auth.GlobalConfiguration;
import com.balcia.auth.HashResult;
import com.balcia.auth.RegisterRequest;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;

@ApplicationScoped
public class SmartIdService {


    SmartIdConfiguration smartIdConfiguration;
    GlobalConfiguration globalConfiguration;

    private SmartIdClient client;

    @Inject
    public SmartIdService(SmartIdConfiguration smartIdConfiguration, GlobalConfiguration globalConfiguration) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        client = new SmartIdClient();

        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(getClass().getResource(globalConfiguration.storeFile()).getPath());
        keyStore.load(fis, globalConfiguration.storePassword().toCharArray());
        client.setTrustStore(keyStore);

        client.setRelyingPartyUUID(smartIdConfiguration.relyingPartyUUID());
        client.setRelyingPartyName(smartIdConfiguration.relyingPartyName());
        client.setHostUrl(smartIdConfiguration.hostUrl());
        this.smartIdConfiguration = smartIdConfiguration;
        this.globalConfiguration = globalConfiguration;
    }

    public HashResult hash() {
        HashResult result = new HashResult();
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        result.authenticationHash = authenticationHash;
        result.verificationCode = authenticationHash.calculateVerificationCode();
        return result;
    }

    public void register(RegisterRequest registerRequest) {
        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64(registerRequest.hashInBase64);
        authenticationHash.setHashType(HashType.valueOf(registerRequest.hashType));

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
                SemanticsIdentifier.IdentityType.PNO,
                SemanticsIdentifier.CountryCode.LV,
                registerRequest.rc);


        client.createAuthentication()
                .withSemanticsIdentifier(semanticsIdentifier)
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(
                        Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
                        ))
                .authenticate();
    }
}
