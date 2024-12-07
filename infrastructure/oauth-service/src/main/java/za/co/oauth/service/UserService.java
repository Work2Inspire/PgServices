package za.co.oauth.service;
//
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import za.co.oauth.repository.UserRepository;
//import za.co.oauth.repository.model.User;

//
//import org.apache.http.impl.auth.BasicScheme;
//import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.impl.client.HttpClients;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.ResponseEntity;
//import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
//import org.springframework.http.client.reactive.ReactorClientHttpConnector;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.HttpClientErrorException;
//import org.springframework.web.client.RestTemplate;
//import org.springframework.web.reactive.function.client.WebClient;
//import org.springframework.web.reactive.function.client.WebClientResponseException;
//import za.co.oauth.config.AuthServer2Config;
//import za.co.oauth.model.UserDTO;
//import za.co.oauth.repository.UserRepository;
//import za.co.oauth.repository.model.User;
//
//import javax.ws.rs.NotFoundException;
//import java.net.http.HttpClient;
//import java.util.Base64;
//import java.util.List;
//
//@Service
//public class UserService {
//
////    @Autowired
//    private UserRepository userRepository;
//    private final RestTemplate restTemplate = new RestTemplate();
////    private AuthServer2Config authServer2Config;
//
//    public User getUserByName(String name) {
//        return userRepository.findByUsername(name);
//    }
//
//    public User fetchUserByUsername(String username) {
//        //return user from the UserService ---make sure it is on
//
//        String userServiceUrl = "http://localhost:9101/users/username/"+username;
////
////        String usernameAndPassword = "u:p";  //Full pass credentials in userService AppProperties
////        String base64Credentials = Base64.getEncoder().encodeToString(usernameAndPassword.getBytes());
////
////        HttpHeaders headers = new HttpHeaders();
////        headers.set("Authorization", "Basic " + base64Credentials);
////        // Send request with authentication headers
////        HttpEntity<String> entity = new HttpEntity<>(headers);
////
////        User foundUser = restTemplate.exchange(userServiceUrl, HttpMethod.GET, entity, User.class).getBody();
////        if (foundUser == null) {
////            throw new UsernameNotFoundException("User not found");
////        }
////        return foundUser;
//        try{
//            return restTemplate.getForObject(userServiceUrl,User.class,username);
//        } catch (Exception e) {
//            throw new UsernameNotFoundException(restTemplate.getForObject(userServiceUrl,User.class,username).toString());
//        }
//
//
////        String accessToken = authServer2Config.getAccessToken();
////
////        HttpHeaders headers = new HttpHeaders();
////        headers.setBearerAuth(accessToken); // Add Bearer token
////        HttpEntity<Void> entity = new HttpEntity<>(headers);
////
////        String userServiceUrl = "http://localhost:9101/users/username/" + username;
////
////        ResponseEntity<User> response = restTemplate.exchange(
////                userServiceUrl,
////                HttpMethod.GET,
////                entity,
////                User.class
////        );
////
////        if (response.getBody() == null) {
////            throw new UsernameNotFoundException("User not found");
////        }
////
////        return response.getBody();
//
//    }
//}
