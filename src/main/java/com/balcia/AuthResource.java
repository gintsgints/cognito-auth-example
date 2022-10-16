package com.balcia;

import com.balcia.auth.HashResult;
import com.balcia.auth.RegisterRequest;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Path("/auth")
public class AuthResource {

    @ConfigProperty(name = "my-trust-store-file")
    String storeFile;
    @ConfigProperty(name = "my-trust-store-password")
    String storePassword;
    @ConfigProperty(name = "smart-id-relying-party-uuid")
    String relyingPartyUUID;
    @ConfigProperty(name = "smart-id-relying-party-name")
    String relyingPartyName;
    @ConfigProperty(name = "smart-id-host-url")
    String hostUrl;
    @ConfigProperty(name = "aws-user-pool-client-id")
    String userPoolClientId;
    @ConfigProperty(name = "aws-user-pool-client-secret")
    String userPoolClientSecret;


    private final CognitoIdentityProviderClient identityProviderClient = CognitoIdentityProviderClient.builder()
            .region(Region.EU_CENTRAL_1)
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIATCGEWISDWB3I2LGU", "mLLb8jllBkyvwNeuiFbUiNlv/ea071tPsGPwa3EJ")))
            .build();

    @GET
    @Path("/hash")
    public HashResult hash() {
        HashResult result = new HashResult();
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        result.authenticationHash = authenticationHash;
        result.verificationCode = authenticationHash.calculateVerificationCode();
        return result;
    }

    @POST
    @Path("/register")
    public String register(RegisterRequest registerRequest) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

        SmartIdClient client = new SmartIdClient();

        System.setProperty("javax.net.ssl.trustStore", getClass().getResource(storeFile).getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", storePassword);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(getClass().getResource(storeFile).getPath());
        keyStore.load(fis, storePassword.toCharArray());
        client.setTrustStore(keyStore);

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64(registerRequest.hashInBase64);
        authenticationHash.setHashType(HashType.valueOf(registerRequest.hashType));

        client.setRelyingPartyUUID(relyingPartyUUID);
        client.setRelyingPartyName(relyingPartyName);
        client.setHostUrl(hostUrl);

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

        List<AttributeType> userAttrsList = new ArrayList<>();

        userAttrsList.add(AttributeType.builder()
                .name("email")
                .value(registerRequest.email)
                .build());

        userAttrsList.add(AttributeType.builder()
                .name("custom:registry_code")
                .value(registerRequest.rc)
                .build());

        SignUpRequest request = SignUpRequest.builder()
                .clientId(userPoolClientId)
                .secretHash(calculateSecretHash(userPoolClientId, userPoolClientSecret, registerRequest.email))
                .username(registerRequest.email)
                .password(registerRequest.password)
                .userAttributes(userAttrsList)
                .build();

        identityProviderClient.signUp(request);

        return "OK";
    }

    public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }

}
