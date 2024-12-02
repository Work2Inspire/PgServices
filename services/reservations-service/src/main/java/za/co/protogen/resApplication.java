package za.co.protogen;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class resApplication {
    public static void main(String[] args) {
        SpringApplication.run(resApplication.class,args);
    }
}