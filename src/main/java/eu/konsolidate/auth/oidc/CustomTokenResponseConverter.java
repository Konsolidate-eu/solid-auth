package eu.konsolidate.auth.oidc;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom OAuth2 access token response converter
 *
 * This class makes sure the access token response from the identity provider is formatted so that it includes:
 * - access token
 * - refresh token
 * - id token
 * - scopes (list)
 */
@Component
public class CustomTokenResponseConverter implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {
    @Override
    public OAuth2AccessTokenResponse convert(Map<String, Object> tokenResponse) {
        String accessToken = getTokenParam(tokenResponse, OAuth2ParameterNames.ACCESS_TOKEN);
        String refreshToken = getTokenParam(tokenResponse, OAuth2ParameterNames.REFRESH_TOKEN);
        long expiresIn = getExpiresInParam(tokenResponse);

        Set<String> scopes = Collections.emptySet();
        if (tokenResponse.containsKey(OAuth2ParameterNames.SCOPE)) {
            String scope = tokenResponse.get(OAuth2ParameterNames.SCOPE).toString();
            scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, ","))
                    .collect(Collectors.toSet());
        }

        Map<String, Object> additionalParameters = new HashMap<>();

        final String ID_TOKEN_PARAMETER_NAME = "id_token";
        additionalParameters.put(ID_TOKEN_PARAMETER_NAME, getTokenParam(tokenResponse, ID_TOKEN_PARAMETER_NAME));

        return OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(expiresIn)
                .scopes(scopes)
                .refreshToken(refreshToken)
                .additionalParameters(additionalParameters)
                .build();
    }

    private String getTokenParam(Map<String, Object> tokenResponse, String parameterName) {
        return tokenResponse.containsKey(parameterName) ? tokenResponse.get(parameterName).toString() : null;
    }

    private long getExpiresInParam(Map<String, Object> tokenResponse) {
        return tokenResponse.containsKey(OAuth2ParameterNames.EXPIRES_IN) ?
                Long.parseLong(tokenResponse.get(OAuth2ParameterNames.EXPIRES_IN).toString()) : -1;
    }
}
