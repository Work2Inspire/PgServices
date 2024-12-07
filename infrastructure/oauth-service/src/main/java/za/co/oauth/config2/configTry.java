package za.co.oauth.config2;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
//import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
//import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.stereotype.Component;
//import org.springframework.web.client.RestTemplate;
//import za.co.oauth.model.UserDTO;
//
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.Arrays;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.UUID;
//
//@Configuration
//@EnableWebSecurity
//public class configTry {
//
//    @Bean
//    public RestTemplate restTemplate() {
//        return new RestTemplate();
//    }
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(
//            HttpSecurity http,
//            RegisteredClientRepository registeredClientRepository,
//            AuthorizationServerSettings authorizationServerSettings,
//            CustomUserDetailsService userDetailsService) throws Exception {
//
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        http
//                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
//                        .accessTokenRequestConverter(new DelegatingAuthenticationConverter(
//                                Arrays.asList(
//                                        new OAuth2AuthorizationCodeAuthenticationConverter(),
//                                        new OAuth2RefreshTokenAuthenticationConverter()
//                                )
//                        ))
//                )
//                .oidc(Customizer.withDefaults());
//
//        http
//                .userDetailsService(userDetailsService);
//
//        return http.build();
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("your-client-id")
//                .clientSecret("{noop}your-client-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://localhost:8080/login/oauth2/code/custom")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(false)
//                        .build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(client);
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://localhost:9000")
//                .build();
//    }
//
//    private static KeyPair generateRsaKey() {
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            return keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//    }
//}
//
//
////    @Bean
////    public RegisteredClientRepository registeredClientRepository() {
////        // Create a client with client_id, client_secret, and authorization flows
////        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
////                .clientId("client-id")
////                .clientSecret(passwordEncoder().encode("makeThisAVeryLongRandomStringAtLeast32Characters"))
////                .scope(OidcScopes.OPENID) // OpenID Connect scope
////                .scope("read")
////                .scope("write")
////                .redirectUri("http://localhost:9000/oauth2/authorize?response_type=code&client_id=client-id&redirect_uri=http://localhost:8080/login/oauth2/code/client") // Client's redirect URI
////                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN)
////                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
////                .build();
////
////        return new InMemoryRegisteredClientRepository(registeredClient);
////    }
////
////    @Bean
////    public PasswordEncoder passwordEncoder() {
////        return new BCryptPasswordEncoder();
////    }
////
////    @Bean
////    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
////        http.csrf(csrf -> csrf.disable())
////                .authorizeHttpRequests(auth -> auth
////                        .requestMatchers("/auth/**").permitAll()
////                        .anyRequest().authenticated());
////        return http.build();
////    }
////
////    @Bean
////    public UserDetailsService users() {
////
////        // Configure in-memory user store with encoded passwords
////        var user = User.withUsername("user")
////                .password(passwordEncoder().encode("password"))
//////                .roles("USER")
////                .build();
////        return new InMemoryUserDetailsManager(user);
//////        return username -> {
//////            if (username.equals("user")) {
//////                return org.springframework.security.core.userdetails.User.builder()
//////                        .username("user")
//////                        .password(passwordEncoder().encode("password"))
//////                        .roles("USER") // Assign ROLE_USER
//////                        .build();
//////            } else if (username.equals("admin")) {
//////                return org.springframework.security.core.userdetails.User.builder()
//////                        .username("admin")
//////                        .password(passwordEncoder().encode("password"))
//////                        .roles("ADMIN") // Assign ROLE_ADMIN
//////                        .build();
//////            }
//////            throw new RuntimeException("User not found");
//////        };
////    }
////
////
////    //Jwt stuff---------------------------------
////    @Bean
////    public JWKSource<SecurityContext> jwkSource() throws Exception {
////        // Generate RSA Key Pair
////        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
////        keyPairGenerator.initialize(2048);
////        KeyPair keyPair = keyPairGenerator.generateKeyPair();
////        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
////        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
////
////        // Create JWK
////        RSAKey rsaKey = new RSAKey.Builder(publicKey)
////                .privateKey(privateKey)
////                .keyID(UUID.randomUUID().toString())
////                .build();
////
////        return (jwkSelector, context) -> jwkSelector.select(new com.nimbusds.jose.jwk.JWKSet(rsaKey));
////    }
////}