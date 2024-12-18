//package za.co.oauth.service;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.core.ParameterizedTypeReference;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.stereotype.Service;
//import org.springframework.util.LinkedMultiValueMap;
//import org.springframework.util.MultiValueMap;
//import org.springframework.web.client.RestTemplate;
//
//import java.util.Map;
//
//@Service
//public class TokenService {
//    private final RestTemplate restTemplate;
//
//    @Autowired
//    public TokenService(RestTemplate restTemplate) {
//        this.restTemplate = restTemplate;
//    }
//
//    public String getAccessToken() {
//        String tokenUrl = "http://localhost:9000/oauth/token";
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//        headers.setBasicAuth("users-client-id", "users-client-secret");
//
//        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
//        body.add("grant_type", "client_credentials");
//
//        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
//
//        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
//
//        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
//            return (String) response.getBody().get("access_token");
//        }
//
//        throw new RuntimeException("Failed to retrieve access token");
//    }
//}