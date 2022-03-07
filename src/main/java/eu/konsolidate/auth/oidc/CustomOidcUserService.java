package eu.konsolidate.auth.oidc;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

/**
 * Custom OIDC user service
 *
 * This class is responsible for fetching user information from the identity provider.
 */
@Component
public class CustomOidcUserService extends OidcUserService {
    /**
     * Fetch user information from the identity provider and wrap in a custom class.
     *
     * @param userRequest request that contains accessToken and id token
     * @return Custom OIDC user class (contains user information)
     * @throws OAuth2AuthenticationException authentication exception
     */
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser loadedUser = super.loadUser(userRequest);

        MyOidcUser user = (MyOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        user.setUserFields(loadedUser);
        return user;
    }
}
