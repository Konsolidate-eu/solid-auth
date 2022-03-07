package eu.konsolidate.auth.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpMethod;

import java.util.Date;
import java.util.UUID;

public class DpopTokenUtils {
    public static String generateDpopToken(String url, HttpMethod method, ECKey privateKey) {
        try {
            ECKey publicKey = privateKey.toPublicJWK();

            JWSSigner signer = new ECDSASigner(privateKey);

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .claim("htu", url)
                    .claim("htm", method.toString())
                    .claim("jti", UUID.randomUUID().toString())
                    .issueTime(new Date())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(publicKey.toPublicJWK()).type(new JOSEObjectType("dpop+jwt")).build(),
                    claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Cannot generate elliptic curve");
        }
    }
}
