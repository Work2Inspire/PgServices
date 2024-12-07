package za.co.oauth.controller;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//@RequestMapping("/.well-known")
//public class JwksController {

//    private final JWKSet jwkSet;
//
//    public JwksController(JWKSet jwkSet) {
//        this.jwkSet = jwkSet;
//    }
//
//    @GetMapping("/jwks.json")
//    public String getJwks() {
//        return jwkSet.toJSONObject().toString(); // Output the JWKS as JSON
//    }
//}