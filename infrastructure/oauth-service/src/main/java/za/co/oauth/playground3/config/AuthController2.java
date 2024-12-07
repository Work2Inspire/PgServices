//package za.co.oauth.playground3.config;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RestController;
//import za.co.oauth.model.UserDTO;
//
//@RestController
//public class AuthController2 {
//    private final AuthenticationManager authenticationManager;
//    private final TokenService tokenService;
//
//    private AuthController2(AuthenticationManager authenticationManager, TokenService tokenService){
//        this.authenticationManager=authenticationManager;
//        this.tokenService=tokenService;
//    }
//    @PostMapping("/login")
//    public ResponseEntity<?> login(@RequestBody UserDTO authRequest) {
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        String token = tokenService.generateToken(authentication);
////        return ResponseEntity.ok(new AuthResponse(token));
//        return null;
//    }
//}
