//package za.co.oauth.config;
//
//import com.nimbusds.jose.jwk.RSAKey;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.jwt.JwtEncoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//
//import java.util.UUID;
//
//@Configuration
//public class oauthResourceServerConfig {
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("client-id")
//                .clientSecret("{noop}client-secret") // Use encoder for production
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scope("read")
//                .scope("write")
//                .redirectUri("http://localhost:9000/login/oauth2/code/")
//                .build();
//
//        return new InMemoryRegisteredClientRepository(client);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//
//
//}
