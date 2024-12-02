package za.co.protogen.config;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@FeignClient(name = "eureka-server.properties")
public interface ReservationFeign {
    @GetMapping("/cars/{id}")
    Object getByVin(@PathVariable String vin);
    @GetMapping("/users/{id}")
    Object getUserById(@PathVariable Long id);

}
