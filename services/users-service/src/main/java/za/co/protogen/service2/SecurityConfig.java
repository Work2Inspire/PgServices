package za.co.protogen.service2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,"/users").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(a->a.loginPage("http://localhost:9000/login"))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())) // Validate JWTs
                .build();
    }
}