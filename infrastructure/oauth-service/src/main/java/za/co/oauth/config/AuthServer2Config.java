package za.co.oauth.config;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.jwt.*;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.util.LinkedMultiValueMap;
//import org.springframework.util.MultiValueMap;
//import org.springframework.web.client.RestTemplate;
//import za.co.oauth.playground3.config.UserDetailsServiceImpl;
//import za.co.oauth.service.UserService;
////import za.co.oauth.playground3.config.UserDetailsServiceImpl;
////import za.co.oauth.service.UserService;
//
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.time.Duration;
//import java.util.Map;
//import java.util.UUID;
//
//@Configuration
//public class AuthServer2Config {
//
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorizeRequests ->
//                        authorizeRequests
//                                .requestMatchers("/login","/oauth2/**","/users/username/**").permitAll() // Secure specific URLs
//                                .anyRequest().authenticated()) // Allow other requests
//                .csrf(csrf -> csrf
//                                .ignoringRequestMatchers("/login", "/oauth2/**"))
//                .formLogin(Customizer.withDefaults()) // Enables default login page
//                .authenticationManager(authenticationManager(new UserDetailsServiceImpl(new UserService()),passwordEncoder()));
//
//        return http.build();
//    }
//
//
////
////    @Bean
////    public RegisteredClientRepository registeredClientRepository() {
////        // Define the client application (e.g., the service on port 9101)
////        RegisteredClient registeredClient = RegisteredClient.withId("1")
////                .clientId("my-client-id")
////                .clientSecret("{noop}my-client-secret") // NoOp for testing only
////                .redirectUri("http://localhost:9101/login/oauth2/code/auth-server")
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .scope("read")
////                .scope("write")
////                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
////                .tokenSettings(TokenSettings.builder()
////                        .accessTokenTimeToLive(Duration.ofMinutes(30))
////                        .refreshTokenTimeToLive(Duration.ofDays(1))
////                        .build())
////                .build();
////
////        // Store the client in memory
////        return new InMemoryRegisteredClientRepository(registeredClient);
////    }
////
////    @Bean
////    public UserDetailsService userDetailsService() {
////        // Set up in-memory users for login
////        return new InMemoryUserDetailsManager(
////                User.withUsername("user1")
////                        .password("password1")
////                        .roles("USER")
////                        .build(),
////                User.withUsername("admin")
////                        .password("adminpass")
////                        .roles("ADMIN")
////                        .build()
////        );
////    }
//
//
//
//
////    @Bean
////    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////        http.formLogin(Customizer.withDefaults()); // Allows users to log in using a form
////        return http.build();
////    }
////
////    @Bean
////    UserDetailsService users() {
////        UserDetails user = User.withDefaultPasswordEncoder()
////                .username("admin")
////                .password("password")
////                .roles("USER")
////                .build();
////        return new InMemoryUserDetailsManager(user);
////    }
//
//
//
////    @Bean
////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
////        http
////                .authorizeHttpRequests(auth -> auth
////                        .requestMatchers("/", "/error").permitAll()
////                        .anyRequest().authenticated()
////                )
////                .oauth2Login(oauth2 -> oauth2
////                        .loginPage("/oauth2/authorization/custom-server")
////                        .authorizationEndpoint(authorization -> authorization
////                                .baseUri("/oauth2/authorization")
////                        )
////                );
////
////        return http.build();
////    }
//
////    @Bean
////    public ClientRegistrationRepository clientRegistrationRepository() {
////        ClientRegistration registration = ClientRegistration
////                .withRegistrationId("custom-server")
////                .clientId("your-client-id")
////                .clientSecret("your-client-secret")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
////                .scope("openid", "profile", "email")
////                .authorizationUri("http://your-auth-server/oauth2/authorize")
////                .tokenUri("http://your-auth-server/oauth2/token")
////                .userInfoUri("http://your-auth-server/userinfo")
////                .userNameAttributeName("sub")
////                .build();
////
////        return new InMemoryClientRegistrationRepository(registration);
////    }
////
////    @Bean
////    UserDetailsService users() {
////        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
////        UserDetails user = User.builder()
////                .username("admin")
////                .password("password")
////                .passwordEncoder(encoder::encode)
////                .roles("USER")
////                .build();
////        return new InMemoryUserDetailsManager(user);
////    }
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//@Bean
//public AuthenticationManager authenticationManager(UserDetailsServiceImpl userDetailsServiceImpl, PasswordEncoder passwordEncoder) {
//
//    var authProvider = new DaoAuthenticationProvider();
//    authProvider.setUserDetailsService(userDetailsServiceImpl);
//    authProvider.setPasswordEncoder(passwordEncoder);
//
//    return new ProviderManager(authProvider);
//}
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
////
////
////    @Bean
////    public JWKSet jwkSet(RSAKey rsaKey) {
////        // Create a JWKSet containing the RSAKey
////        return new JWKSet(rsaKey);
////    }
////    @Bean
////    public JwtEncoder jwtEncoder() {
////        // In production, use proper key management
////        KeyPair keyPair = generateRsaKey();
////        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(
////                new JWKSet(rsaKey(keyPair))
////        );
////        return new NimbusJwtEncoder(jwks);
////    }
////
////    @Bean
////    public JwtDecoder jwtDecoder() {
////        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) generateRsaKey().getPublic())
////                .build();
////    }
////
////    @Bean
////    public KeyPair generateRsaKey() {
////        try {
////            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
////            generator.initialize(2048);
////            return generator.generateKeyPair();
////        } catch (Exception e) {
////            throw new RuntimeException("Error generating RSA keys", e);
////        }
////    }
////    @Bean
////    public RSAKey rsaKey(KeyPair keyPair) {
////        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
////        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
////        return new RSAKey.Builder(publicKey)
////                .privateKey(privateKey)
////                .keyID(UUID.randomUUID().toString())
////                .build();
////    }
////    @Bean
////    public RestTemplate restTemplate() {
////        return new RestTemplate();
////    }
////
//}
//
//
//
//
//
//
//
//
//
//
//
//
