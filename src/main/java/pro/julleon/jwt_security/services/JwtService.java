package pro.julleon.jwt_security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    public static final String SECRET_KEY = "305c300d06092a864886f70d0101010500034b00304802410093c0548c46975bc81917c04f12c3f95a70a0ea7107bbfe6ca6a87ead01d0441261e9f00b57f98576e9a3b51cc4cd7015b8921e553b977810263ac9eafc36bd810203010001";



    public String generateJwt(UserDetails userDetails) {
        return generateJwt(new HashMap<>(), userDetails);
    }

    public String generateJwt(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiredAt = new Date(System.currentTimeMillis() + 24 * 60 * 1000);
        String username = userDetails.getUsername();
        extraClaims.put("sub", username);
        return Jwts
                .builder()
                .setSubject(username)
                .setClaims(extraClaims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiredAt)
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isJwtValid(String jwt, UserDetails userDetails) {
        final String userName = extractUsername(jwt);
        return (userName.equals(userDetails.getUsername())) && !isJwtExpired(jwt);
    }

    private boolean isJwtExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt, Claims::getExpiration);
    }

    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }

    public <T> T extractClaim(String jwt, Function<Claims, T> claimsTResolver) {
        final Claims claims = extreactAllClaims(jwt);
        return claimsTResolver.apply(claims);
    }


    public Claims extreactAllClaims(String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
