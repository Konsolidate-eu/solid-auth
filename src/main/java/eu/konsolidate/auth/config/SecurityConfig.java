package eu.konsolidate.auth.config;

import eu.konsolidate.auth.oidc.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOidcUserService customOidcUserService;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomAccessTokenResponseClient customAccessTokenResponseClient;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                // MAKE SURE AUTHENTICATION IS REQUIRED FOR ALL REQUESTS
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                // CONFIGURE OAUTH2 - OIDC AUTHENTICATION
                .oauth2Login()
                // CONFIGURE THE AUTHORIZATION ENDPOINT
                .authorizationEndpoint()
                    // CUSTOM AUTHORIZATION REQUEST RESOLVER
                    .authorizationRequestResolver(customAuthorizationRequestResolver)
                .and()
                // CONFIGURE THE ACCESS TOKEN REQUEST
                .tokenEndpoint()
                    // CUSTOM ACCESS TOKEN RESPONSE CLIENT
                    .accessTokenResponseClient(customAccessTokenResponseClient)
                .and()
                // CONFIGURE USER INFO REQUEST
                .userInfoEndpoint()
                    // CUSTOM OIDC USER SERVICE
                    .oidcUserService(customOidcUserService)
                .and()
                // CUSTOM SUCCESS HANDLER FOR OAUTH2 - OIDC FLOW
                .successHandler(customAuthenticationSuccessHandler)
                .and()
                // CONFIGURE CUSTOM LOGOUT LOGIC
                .logout()
                    // CUSTOM LOGOUT SUCCESS HANDLER
                    .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                .and()
                // CONFIGURE EXCEPTION HANDLING
                .exceptionHandling()
                    // RETURN STATUS 401 UNAUTHORIZED WHEN NOT AUTHENTICATED
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    }
}
