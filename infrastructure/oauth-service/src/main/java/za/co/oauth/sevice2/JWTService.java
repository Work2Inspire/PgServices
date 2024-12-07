package za.co.oauth.sevice2;
//
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//import javax.crypto.spec.SecretKeySpec;
//import java.security.Key;
//import java.util.Base64;
//import java.util.Date;
//
//@Service
//public class JWTService {
//
//    @Value("${jwt.secret}")
//    private String secret;
//
//    public String createToken(String username) {
//        // Convert the secret into a byte array and create a key
//        byte[] keyBytes = Base64.getDecoder().decode(secret);
//        Key key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
//                .signWith(SignatureAlgorithm.HS256,key)
//                .compact();
//    }
//}

