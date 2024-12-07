package za.co.oauth.controller2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import za.co.oauth.playground3.config.UsersServiceClient;
import za.co.oauth.repository.UserRepository;

@RestController
public class OauthController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UsersServiceClient usersServiceClient;

    @GetMapping
    public String home(){
//        UserDetails details = usersServiceClient.fetchUserByUsername(principal.getName());
        return "Hello username: ";
    }
}
