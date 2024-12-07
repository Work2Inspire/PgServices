package za.co.oauth.controller;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//import za.co.oauth.repository.model.User;
//import za.co.oauth.service.UserService;
//
//@RestController
//@RequestMapping("/oauth")
//public class OauthController {
//
//    @Autowired
//    private UserService userService;
//
//    @GetMapping("/authorize")
//    public User getUser(@RequestParam String name) {
//        return userService.getUserByName(name);
//    }
//}
//






//    @RequestMapping("/")
//    public String home(){
//        return "welcome";
//    }
//
//    @RequestMapping("/user")
//    public Principal user(Principal user){
//        return user;
//    }
//}
//



//@RestController
//@RequestMapping("/api/auth")
//public class OauthController {
//
//    private final UserService userService;
//    private final JwtEncoder jwtEncoder;
//
//    public OauthController(UserService userService, JwtEncoder jwtEncoder) {
//        this.userService = userService;
//        this.jwtEncoder = jwtEncoder;
//    }
//
//    // Registration endpoint
//    @PostMapping("/register")
//    public ResponseEntity<String> register(@RequestBody UserDTO userDTO) {
//        userService.createUser(userDTO.getUsername(), userDTO.getPassword());
//        return ResponseEntity.ok("User registered successfully");
//    }
//
//    // Login endpoint
//    @PostMapping("/token")
//    public ResponseEntity<String> token(@RequestBody UserDTO userDTO) {
//        // Check username and password
//        if (userService.validateUser(userDTO.getUsername(), userDTO.getPassword())) {
//            // Create JWT token
//            JwtClaimsSet claims = JwtClaimsSet.builder()
//                    .subject(userDTO.getUsername())
//                    .expiresAt(Instant.now().plusSeconds(3600)) // Token expires in 1 hour
//                    .build();
//
//            String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
//            return ResponseEntity.ok(token);
//        }
//
//        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//    }
//
//    private String createToken(String username) {
//        Instant now = Instant.now();
//
//        JwtClaimsSet claims = JwtClaimsSet.builder()
//                .issuer("self")
//                .issuedAt(now)
//                .expiresAt(now.plus(1, ChronoUnit.HOURS))
//                .subject(username)
//                .build();
//
//        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
//    }
//
//
//}
//
//
//
//
//
////
////    //    @Autowired
////    private AuthenticationManager authenticationManager;
////    //    @Autowired
////    private TokenService tokenService;
////
////    @PostMapping("/login")
////    public ResponseEntity<?> login(@RequestBody LoginRequestDto requestDto) {
//////        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(requestDto.getUsername(), requestDto.getPassword());
//////        authenticationManager.authenticate(authToken);
//////        // Return a generated JWT token (implement JWT token creation here)
//////        return "Token";
//////    }
////
////        Authentication authentication = authenticationManager.authenticate(
////                new UsernamePasswordAuthenticationToken(
////                        requestDto.getUsername(),
////                        requestDto.getPassword()));
////
////        // Use allocateToken to generate token
////        String extendedInfo = authentication.getName(); // Use username or other details
////        Token token = tokenService.allocateToken(extendedInfo);
////
////        return ResponseEntity.ok(new TokenResponse(token.getKey()));
////
////        // Manually create the JWT
//////        Jwt jwt = jwtEncoder.encode(j -> j
//////                .header("alg", "RS256")
//////                .claim("sub", authentication.getName()) // Typically username as subject
//////                .claim("roles", authentication.getAuthorities()) // Add user roles as claim
//////                .issuedAt(Instant.now())
//////                .expiresAt(Instant.now().plusSeconds(3600)) // 1 hour expiration time
//////        );
//////        return ResponseEntity.ok(new TokenResponse(jwt.getTokenValue()));
////    }
////
////}