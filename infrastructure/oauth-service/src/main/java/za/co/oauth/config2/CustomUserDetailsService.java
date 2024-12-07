package za.co.oauth.config2;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestClientException;
//import org.springframework.web.client.RestTemplate;
//
//import java.util.Collections;
//
//@Service
//@RequiredArgsConstructor
//public class CustomUserDetailsService implements UserDetailsService {
//    private final RestTemplate restTemplate;
//
//    @Value("${users.service.url}")
//    private String usersServiceUrl;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        try {
//            User user = restTemplate.getForObject(
//                    usersServiceUrl + "/users/{username}",
//                    User.class,
//                    username
//            );
//
//            if (user == null) {
//                throw new UsernameNotFoundException("User not found: " + username);
//            }
//
//            return org.springframework.security.core.userdetails.User
//                    .withUsername(user.getUsername())
//                    .password(user.getPassword()) // Ensure this is already encoded
//                    .authorities(Collections.emptyList()) // No roles for simplicity
//                    .build();
//        } catch (RestClientException e) {
//            throw new UsernameNotFoundException("Error fetching user: " + username, e);
//        }
//    }
//}
