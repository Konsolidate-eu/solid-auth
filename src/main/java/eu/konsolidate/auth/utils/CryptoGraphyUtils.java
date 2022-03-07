package eu.konsolidate.auth.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.util.UUID;

public class CryptoGraphyUtils {
    public static ECKey generateECKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException e) {
            throw new RuntimeException("Cannot generate ECKey");
        }
    }
}
