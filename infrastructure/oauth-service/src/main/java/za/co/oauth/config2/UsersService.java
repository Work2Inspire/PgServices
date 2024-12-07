package za.co.oauth.config2;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestClientException;
//import org.springframework.web.client.RestTemplate;
//
//@Service
//@RequiredArgsConstructor
//public class UsersService {
//    private final RestTemplate restTemplate;
//
//    @Value("${users.service.url}")
//    private String usersServiceUrl;
//
//    public User getUserInfo(String username) {
//        try {
//            return restTemplate.getForObject(
//                    usersServiceUrl + "/users/{username}",
//                    User.class,
//                    username
//            );
//        } catch (RestClientException e) {
//            throw new UsernameNotFoundException("User not found: " + username);
//        }
//    }
//}
