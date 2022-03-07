package eu.konsolidate.auth.oidc;

import com.nimbusds.jose.jwk.ECKey;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Map;

public class MyOidcUser implements OidcUser {
    private final ECKey ecKey;
    private Map<String, Object> claims;
    private OidcUserInfo oidcUserInfo;
    private OidcIdToken oidcIdToken;
    private Map<String, Object> attributes;
    private Collection<? extends GrantedAuthority> authorities;

    public MyOidcUser(ECKey ecKey) {
        this.ecKey = ecKey;
    }

    public ECKey getEcKey() {
        return this.ecKey;
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return this.oidcUserInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return this.oidcIdToken;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getName() {
        return this.claims.get("sub").toString();
    }

    public void setUserFields(OidcUser oidcUser) {
        this.claims = oidcUser.getClaims();
        this.oidcUserInfo = oidcUser.getUserInfo();
        this.oidcIdToken = oidcUser.getIdToken();
        this.attributes = oidcUser.getAttributes();
        this.authorities = oidcUser.getAuthorities();
    }
}
