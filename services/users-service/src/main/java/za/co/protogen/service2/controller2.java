package za.co.protogen.service2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import za.co.protogen.controller.UsersServiceApiController;
import za.co.protogen.persistence.User;
import za.co.protogen.persistence.repository.UserRepository;

import java.security.Principal;

@RestController
public class controller2 {

    private UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(controller2.class);

    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint!";
    }

    @GetMapping("/secured")
    public String securedEndpoint(Principal principal) {
        return "This is a secured endpoint. Welcome, " + principal.getName() + "!";
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<User> findByUsername(@PathVariable String username){
        logger.info("finding user with username: {}",username);
        return ResponseEntity.ok(userRepository.findAll().stream().filter(a->a.getUsername().equals(username)).findFirst().orElse(null));
    }
}

