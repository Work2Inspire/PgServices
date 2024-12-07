package za.co.oauth.playground3.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private UsersServiceClient usersServiceClient;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // (1)
                .authorizeHttpRequests( auth -> auth
                        .requestMatchers("/oauth2/token").permitAll()
                        .anyRequest().authenticated() // (2)
                )
                .formLogin(form->form.permitAll())
                .oauth2ResourceServer(a->a.jwt(Customizer.withDefaults()))
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // (3)
                .httpBasic(Customizer.withDefaults()) // (4)
                .build();
    }
    //2 ways of adding a user to an inmemory database
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("u")
//                .password(new BCryptPasswordEncoder().encode("p"))
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }
//    @Bean
//    public InMemoryUserDetailsManager users() {
//        return new InMemoryUserDetailsManager(
//                User.withUsername("u")
//                        .password("{noop}p")
//                        .authorities("read")
//                        .build()
//        );
//    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaKey) {
        // Create a JWKSet containing the RSAKey
        return new JWKSet(rsaKey);
    }
    @Bean
    public JwtEncoder jwtEncoder() {
        // In production, use proper key management
        KeyPair keyPair = generateRsaKey();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(
                new JWKSet(rsaKey(keyPair))
        );
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) generateRsaKey().getPublic())
                .build();
    }

    @Bean
    public KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generating RSA keys", e);
        }
    }
    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
