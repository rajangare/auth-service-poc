package com.poc.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.securityContext((securityContext) -> securityContext
                .requireExplicitSave(true)
        );

        http.csrf(csrf -> csrf.disable());

        http.authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/login")
                        .authenticated()
                        .anyRequest().authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(customAuthenticationEntryPoint));

        /*http.oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authorization -> authorization
                        .baseUri("/api/login")
                        .authorizationRequestRepository(this.authorizationRequestRepository()))
                .userInfoEndpoint((userInfo) -> userInfo
                        .userAuthoritiesMapper(grantedAuthoritiesMapper())
                )
                .tokenEndpoint(token -> token
                        .accessTokenResponseClient(accessTokenResponseClient()))

        );*/

        http.authenticationManager(this.authenticationManager());


        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*private GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach((authority) -> {
                GrantedAuthority mappedAuthority;

                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority userAuthority = (OidcUserAuthority) authority;
                    mappedAuthority = new OidcUserAuthority(
                            "ROLE_USER", userAuthority.getIdToken(), userAuthority.getUserInfo());
                } else if (authority instanceof OAuth2UserAuthority) {
                    OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) authority;
                    mappedAuthority = new OAuth2UserAuthority(
                            "ROLE_USER", userAuthority.getAttributes());
                } else {
                    mappedAuthority = authority;
                }

                mappedAuthorities.add(mappedAuthority);
            });

            return mappedAuthorities;
        };
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {

        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(customGitLabExpiresInRestTemplate());
        return accessTokenResponseClient;
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshCustomGitLabExpiresInAccessTokenResponseClient() {
        DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient =
                new DefaultRefreshTokenTokenResponseClient();
        refreshTokenTokenResponseClient.setRestOperations(customGitLabExpiresInRestTemplate());
        return refreshTokenTokenResponseClient;
    }

    private static RestTemplate customGitLabExpiresInRestTemplate() {
        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
                new OAuth2AccessTokenResponseHttpMessageConverter();
        tokenResponseHttpMessageConverter.setTokenResponseConverter(customGitLabExpiresInTokenResponseConverter());
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        return restTemplate;
    }

    private static Converter<Map<String, String>, OAuth2AccessTokenResponse> customGitLabExpiresInTokenResponseConverter() {
        MapOAuth2AccessTokenResponseConverter mapOAuth2AccessTokenResponseConverter = new MapOAuth2AccessTokenResponseConverter();
        return tokenResponseParameters -> {
            OAuth2AccessTokenResponse original = mapOAuth2AccessTokenResponseConverter.convert(tokenResponseParameters);
            String expiresIn = tokenResponseParameters.get(OAuth2ParameterNames.EXPIRES_IN);
            if (expiresIn != null) {
                return original;
            }
            OAuth2AccessToken accessToken = original.getAccessToken();
            return OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                    .tokenType(accessToken.getTokenType())
                    .scopes(accessToken.getScopes())
                    .expiresIn(Duration.ofDays(1).toSeconds())
                    .refreshToken(original.getRefreshToken().getTokenValue())
                    .additionalParameters(original.getAdditionalParameters())
                    .build();
        };
    }*/

   /* @Bean
    public PasswordEncoder passwordEncoder() {
        return SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
    }*/
}
