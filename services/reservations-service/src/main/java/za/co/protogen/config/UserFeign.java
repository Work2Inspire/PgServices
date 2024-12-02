package za.co.protogen.config;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@FeignClient(name = "users-service")
public interface UserFeign {
    @GetMapping("/users/{id}")
    Object getUserById(@PathVariable Long id);
}
