package za.co.oauth.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
//
//import java.time.Duration;
//
//@Configuration
//public class ClientConfig {

//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        // Define the client application (e.g., the service on port 9101)
//        RegisteredClient registeredClient = RegisteredClient.withId("1")
//                .clientId("my-client-id")
//                .clientSecret("{noop}my-client-secret") // NoOp for testing only
//                .redirectUri("http://localhost:9101/login/oauth2/code/auth-server")
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .scope("read")
//                .scope("write")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .tokenSettings(TokenSettings.builder()
//                        .accessTokenTimeToLive(Duration.ofMinutes(30))
//                        .refreshTokenTimeToLive(Duration.ofDays(1))
//                        .build())
//                .build();
//
//        // Store the client in memory
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//}
