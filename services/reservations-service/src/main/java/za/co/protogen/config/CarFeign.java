package za.co.protogen.config;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@FeignClient(name = "cars-service")
public interface CarFeign {
    @GetMapping("/cars/{vin}")
    Object getByVin(@PathVariable String vin);
}
