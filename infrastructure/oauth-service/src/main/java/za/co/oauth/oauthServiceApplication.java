package za.co.oauth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
//import za.co.oauth.playground3.config.UserSynService;
import za.co.oauth.repository.model.User;

@SpringBootApplication
public class oauthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(oauthServiceApplication.class,args);
    }

//    private UserSynService service;
//    @EventListener(ApplicationReadyEvent.class)
//    public void syncOnStartup() {
//        service.syncUsers();
//    }
}

