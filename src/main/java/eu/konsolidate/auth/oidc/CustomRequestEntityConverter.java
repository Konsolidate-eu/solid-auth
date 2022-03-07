package eu.konsolidate.auth.oidc;

import com.nimbusds.jose.jwk.ECKey;
import eu.konsolidate.auth.utils.CryptoGraphyUtils;
import eu.konsolidate.auth.utils.DpopTokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

/**
 * Custom OAuth2 authorization code grant request converter
 *
 * This class makes sure the authorization code grant request will include a DPoP proof JWT token
 * as specified in the SOLID OIDC Primer. {@see https://solid.github.io/solid-oidc/primer/}
 */
@Component
@RequiredArgsConstructor
public class CustomRequestEntityConverter implements
        Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {
    private final OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    public CustomRequestEntityConverter() {
        defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
        RequestEntity<?> entity = defaultConverter.convert(req);
        return new RequestEntity<>(getParameters(entity), getHeaders(entity), entity.getMethod(), entity.getUrl());
    }

    private MultiValueMap<String, String> getParameters(RequestEntity<?> entity) {
        return (MultiValueMap<String,String>) entity.getBody();
    }

    /**
     * 1) Fetch the headers from the default request
     * 2) Generate a Cryptographical Elliptic Curve key
     * 3) Sign a JWT with the private Elliptic Curve key generated in step 2 (also include the request url and method)
     * 4) Set the Spring SecurityContext with a new {@link MyOidcUser} with the Elliptic Curve key (because we need
     *    the key later in the process)
     * 5) Set the signed JWT token in the headers of the request
     *
     * @param entity default authorization code grant request to modify
     * @return modified request (with DPoP proof JWT)
     */
    private HttpHeaders getHeaders(RequestEntity<?> entity) {
        // 1)
        HttpHeaders headers = HttpHeaders.writableHttpHeaders(entity.getHeaders());

        // 2)
        ECKey privateKey = CryptoGraphyUtils.generateECKey();
        // 3)
        String dpopToken = DpopTokenUtils.generateDpopToken(entity.getUrl().toString(), HttpMethod.POST, privateKey);

        // 4)
        Authentication authentication = new UsernamePasswordAuthenticationToken(new MyOidcUser(privateKey), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 5)
        headers.add("DPoP", dpopToken);
        return headers;
    }
}