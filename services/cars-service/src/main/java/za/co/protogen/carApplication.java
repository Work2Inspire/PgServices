package za.co.protogen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.SpringApplication;

@SpringBootApplication
public class carApplication {//9102
    private static final Logger logger = LoggerFactory.getLogger(carApplication.class);
    public static void main(String[] args) {
        SpringApplication.run(carApplication.class,args);
        logger.info("Example log from {}", carApplication.class.getSimpleName());
    }
}
