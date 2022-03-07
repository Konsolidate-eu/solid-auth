package eu.konsolidate.auth.oidc;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

/**
 * Custom authorization request resolver
 *
 * This class makes sure the authorization request is built correctly.
 */
@Component
@RequiredArgsConstructor
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private final ClientRegistrationRepository clientRegistrationRepository;

    private final StringKeyGenerator secureKeyGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    /**
     * Customize the OAuth2 - OIDC authorization request.
     * 1) Fetch the configured authorizationUri, clientId, clientSecret, ... for the identity provider and
     *    bundle in a {@link OAuth2AuthorizationRequest}
     * 2) Customize the default request with our own additional parameters
     *
     * @param servletRequest the request to our server (where we fetch the clientRegistrationId from - which is the
     *                       identity provider name that we use for step 1)
     * @return customized authorization request
     */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest servletRequest) {
        OAuth2AuthorizationRequest req = getDefaultResolver().resolve(servletRequest);
        return customizeAuthorizationRequest(req);
    }

    /**
     * Customize the OAuth2 - OIDC authorization request.
     * 1) Fetch the configured authorizationUri, clientId, clientSecret, ... for the identity provider and
     *    bundle in a {@link OAuth2AuthorizationRequest}
     * 2) Customize the default request with our own additional parameters
     *
     * @param servletRequest the request to our server
     * @param clientRegistrationId identity provider name that we use for step 1
     * @return customized authorization request
     */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest servletRequest, String clientRegistrationId) {
        OAuth2AuthorizationRequest req = getDefaultResolver().resolve(servletRequest, clientRegistrationId);
        return customizeAuthorizationRequest(req);
    }

    private DefaultOAuth2AuthorizationRequestResolver getDefaultResolver() {
        return new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    /**
     * Customize the authorization request
     *
     * Customization:
     * 1) Remove the nonce from the request
     * 2) Generate code challenge and verifier
     *
     * Copy the rest of the variables to build a customized version of the request
     *
     * @param req the request that needs to be customized
     * @return customized authorization request
     */
    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest req) {
        if (req == null) { return null; }

        // 1)
        Map<String, Object> attributes = removeNonce(req.getAttributes());
        Map<String, Object> additionalParameters = removeNonce(req.getAdditionalParameters());

        // 2)
        final String CODE_VERIFIER = generateCodeVerifier();
        final String CODE_CHALLENGE = generateCodeChallenge(CODE_VERIFIER);
        final String CODE_VERIFIER_NAME = "code_verifier";
        final String CODE_CHALLENGE_METHOD = "S256";

        attributes.put(CODE_VERIFIER_NAME, CODE_VERIFIER);
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, CODE_CHALLENGE);
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD);

        final String AUTH_REQUEST_URL = buildRequestUrl(req, CODE_CHALLENGE, CODE_CHALLENGE_METHOD);

        return OAuth2AuthorizationRequest
                .authorizationCode()
                .authorizationUri(req.getAuthorizationUri())
                .clientId(req.getClientId())
                .redirectUri(req.getRedirectUri())
                .scopes(req.getScopes())
                .state(req.getState())
                .authorizationRequestUri(AUTH_REQUEST_URL)
                .attributes(attributes)
                .additionalParameters(additionalParameters)
                .build();
    }

    private String buildRequestUrl(OAuth2AuthorizationRequest req, final String CODE_CHALLENGE, final String CODE_CHALLENGE_METHOD) {
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(req.getAuthorizationRequestUri()).build();
        MultiValueMap<String, String> arg = new LinkedMultiValueMap<>(uriComponents.getQueryParams());
        arg.remove("nonce");

        return UriComponentsBuilder
                .fromUriString(req.getAuthorizationUri())
                .queryParams(arg)
                .queryParam(PkceParameterNames.CODE_CHALLENGE, CODE_CHALLENGE)
                .queryParam(PkceParameterNames.CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD)
                .build()
                .toUriString();
    }

    private Map<String, Object> removeNonce(Map<String, Object> map) {
        Map<String, Object> mapWithoutNonce = new HashMap<>(map);
        mapWithoutNonce.remove("nonce");
        return mapWithoutNonce;
    }

    private String generateCodeChallenge(final String CODE_VERIFIER) {
        try {
            return createHash(CODE_VERIFIER);
        } catch (NoSuchAlgorithmException ignored) {
            throw new RuntimeException("Cannot create code challenge");
        }
    }

    private String generateCodeVerifier() {
        return this.secureKeyGenerator.generateKey();
    }

    private static String createHash(final String CODE_VERIFIER) throws NoSuchAlgorithmException {
        final String ALGORITHM = "SHA-256";
        MessageDigest md = MessageDigest.getInstance(ALGORITHM);
        byte[] digest = md.digest(CODE_VERIFIER.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
