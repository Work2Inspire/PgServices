package za.co.oauth.playground3.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import za.co.oauth.repository.UserRepository;
import za.co.oauth.repository.model.User;

import java.util.List;

//@Service
//public class UserSynService {
//
//    private static final Logger logger = LoggerFactory.getLogger(UserSynService.class);
//    private final UsersServiceClient usersServiceClient; // Your WebClient logic here
//    private final UserRepository userRepository; // Local repository
//
//    public UserSynService(UsersServiceClient usersServiceClient, UserRepository userRepository) {
//         this.usersServiceClient = usersServiceClient;
//        this.userRepository = userRepository;
//    }
//
//    @Scheduled(fixedRate = 60000) // Sync every 1 minute
//    public void syncUsers() {
//
//        try {
//            logger.info("Starting user synchronization...");
//
//            List<User> ListToSave = usersServiceClient.fetchAllUsers();
//            userRepository.saveAll(ListToSave);
//
//            logger.info("User synchronization completed successfully.");
//        } catch (Exception e) {
//            logger.error("Error during user synchronization: ", e);
//        }
//    }
//}