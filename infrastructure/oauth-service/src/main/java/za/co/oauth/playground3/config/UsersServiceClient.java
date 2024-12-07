package za.co.oauth.playground3.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import za.co.oauth.repository.model.User;

import java.util.List;
import java.util.Map;

@Service
public class UsersServiceClient {

    private static final Logger logger = LoggerFactory.getLogger(UsersServiceClient.class);
    private String oauthServerUrl="http://localhost:9000";
    private String clientId="usersServiceClient";
    private String clientSecret="usersServiceSecret";

    private final RestTemplate restTemplate;
    private final PasswordEncoder passwordEncoder;

    public UsersServiceClient(RestTemplate restTemplate, PasswordEncoder passwordEncoder) {
        this.restTemplate=restTemplate;
        this.passwordEncoder=passwordEncoder;
    }

    public String fetchAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("scope", "read");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    oauthServerUrl + "/oauth2/token",  // Note: changed from /oauth/token to /oauth2/token
                    HttpMethod.POST,
                    request,
                    Map.class
            );

            return (String) response.getBody().get("access_token");
        } catch (Exception e) {
            logger.error("Error fetching access token", e);
            return null;
        }
    }








//    private static final Logger logger = LoggerFactory.getLogger(UsersServiceClient.class);
//    private final WebClient webClient;
//    private final PasswordEncoder passwordEncoder;
//
//    public UsersServiceClient(WebClient.Builder webClientBuilder, PasswordEncoder passwordEncoder) {
//        this.webClient = webClientBuilder.baseUrl("http://localhost:9101").build();
//        this.passwordEncoder=passwordEncoder;
//    }
//
//
//    public List<User> fetchAllUsers(){
//
//        String accessToken = fetchAccessToken();
//        return webClient.get()
//                .uri("/users") // Example endpoint in usersService
//                .headers(headers -> headers.setBearerAuth(accessToken))
//                .retrieve()
//                .bodyToFlux(User.class)
//                .collectList()
//                .block();
//
//    }
//
//    public UserDetails fetchUserByUsername(String username) {
//        // Obtain a token using client credentials grant
//        String accessToken = fetchAccessToken();
//
//        // Call usersService with the token
//        return webClient.get()
//                .uri("/username/" + username) // Example endpoint in usersService
//                .headers(headers -> {
//                    assert accessToken != null;
//                    headers.setBearerAuth(accessToken);
//                })
//                .retrieve()
//                .bodyToMono(UserDetails.class)
//                .block();
//    }
//
//    public String fetchAccessToken() {
//        // Call the OAuth server to get a token
//        try {
//            WebClient tokenClient = WebClient.builder().build();
//
//            return tokenClient.post()
//                    .uri("http://localhost:9000/oauth/token")
//                    .headers(headers -> headers.setBasicAuth("usersServiceClient", passwordEncoder.encode("usersServiceSecret")))
//                    .bodyValue("grant_type=client_credentials&scope=read")
//                    .retrieve()
//                    .bodyToMono(Map.class)
//                    .map(response -> (String) response.get("access_token"))
//                    .block();
//
//        } catch (Exception e) {
//            logger.error("error fetching access token",e); // Log the error
//            return null;
//        }
//    }
}
