# Solid auth with Spring Boot and Spring Security

Solid Authentication combined with Spring Boot.
This project demonstrates the Solid Authentication process (OAuth2 - OIDC as specified in the [Solid OIDC Primer](https://solid.github.io/solid-oidc/primer/)) combined with [Spring Boot](https://spring.io/projects/spring-boot) and [Spring Security](https://spring.io/projects/spring-security)).

You can find extra explanation for this repository in the [document](https://www.konsolidate.eu/stories/solid-spring) we posted on the Konsolidate website.

Remark: this code is not tested for production and may be outdated at any point in time. 

## ⚡ Requirements
- [JDK](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
- [Maven](https://maven.apache.org/download.cgi)
- [Community Solid Server](https://github.com/solid/community-server)

## 💻 Running the application locally
There are several ways to run a Spring Boot application on your local machine. One way is to execute the `main` method in the `eu.konsolidate.auth.AuthApplication` class from your IDE.

Alternatively you can use the [Spring Boot Maven plugin](https://docs.spring.io/spring-boot/docs/current/reference/html/build-tool-plugins-maven-plugin.html) like so:
```shell
mvn spring-boot:run
```

## 📃 Client registration
You need to register your application at the identity provider of your choosing. You can do that by sending a POST request to the correct url from your identity provider. You can check the OpenId Configuration from your identity povider at (there you will find a JSON string with "registration_endpoint"):
```shell
https://YOUR_IDENTITY_PROVIDER/.well-known/openid-configuration
```
`Keep in mind that you should execute this request with a body.`

#### Request body
|Parameter|Value
|-|-
| redirect_uris | ["YOUR_REDIRECT_URIS", "...", "..."]
| application_type | "web"
| token_endpoint_auth_method | "authorization_code"
| scopes | "openid,webid,offline_access"

#### Explaining the redirect uris
- see application.yml for "{baseUrl}/login/oauth2/code/{registrationId}",
- it contains the baseUrl from your application (when running locally: http://localhost:8080),
- and also the registrationId (which can be: "community-solid-server", "inrupt" or "solidcommunity")

#### Response
Your identity provider should respond with "client_id" and "client_secret" (and also some other fields which we don't use in this application).

## 🗃 Environment variables
The application uses [environment variables](https://docs.spring.io/spring-boot/docs/1.5.6.RELEASE/reference/html/boot-features-external-config.html) for securing id's and secrets. The mandatory environment variables are listed below:
### In application.yml
##### [Community Solid Server](https://github.com/solid/community-server)
- CSS_CLIENT_ID
- CSS_CLIENT_SECRET
##### [Solidcommunity](https://solidcommunity.net/)
- SOLIDCOMMUNITY_CLIENT_ID
- SOLIDCOMMUNITY_CLIENT_SECRET
##### [Inrupt](https://inrupt.net/)
- INRUPT_CLIENT_ID
- INRUPT_CLIENT_SECRET
- REDIRECT_URL
### In CustomAuthenticationSuccessHandler
- REDIRECT_URL

## 📜 License
The Solid Auth code is copyrighted by [Konsolidate](https://www.konsolidate.eu/)
and available under the [MIT License](https://github.com/Konsolidate-eu/solid-auth/blob/main/LICENSE).
