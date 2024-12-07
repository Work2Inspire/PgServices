package za.co.oauth.playground3.config;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

////import za.co.oauth.model.UserDTO;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final RestTemplate restTemplate;
    private final String usersServiceUrl = "http://localhost:9101";

    private final UsersServiceClient userService;
    private final PasswordEncoder passwordEncoder;
    private final AuthController authController;

    public CustomUserDetailsService(UsersServiceClient userService, PasswordEncoder passwordEncoder, RestTemplate restTemplate, AuthController authController) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.restTemplate = restTemplate;
        this.authController=authController;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username.equals("usersServiceClient")) {
            // Special case for client_credentials flow - avoid the loop
            return User.builder()
                    .username("service_account")
                    .password(passwordEncoder.encode("not_used"))
                    .roles("SERVICE")
                    .build();
        }

        String accessToken = userService.fetchAccessToken();
        if (accessToken == null) {
            throw new UsernameNotFoundException("Could not authenticate with user service");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<?> entity = new HttpEntity<>(headers);

            ResponseEntity<za.co.oauth.repository.model.User> response = restTemplate.exchange(
                    usersServiceUrl + "/users/{username}",
                    HttpMethod.GET,
                    entity,
                    za.co.oauth.repository.model.User.class,
                    username
            );

            za.co.oauth.repository.model.User user = response.getBody();
            if (user == null) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            return User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
//                    .roles(user.getRoles().toArray(new String[0]))
                    .build();
        } catch (Exception e) {
            throw new UsernameNotFoundException("Error fetching user: " + username, e);
        }
    }
}


//        String accessTkn = userService.fetchAccessToken();
//        // Replace this with actual database retrieval logic
//        if (!username.isBlank()) {
//            return User.builder()
//                    .username("user")
//                    .password(passwordEncoder.encode("password"))
//                    .roles("USER") // Role assignment
//                    .build();
//        }
//        throw new UsernameNotFoundException("User not found");
//    }
//}
