package io.javabrains.springsecurityjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {


    public String extractUsername(String token, PublicKey publicKey) {
        return extractClaim(token, Claims::getSubject, publicKey);
    }

    public Date extractExpiration(String token,PublicKey publicKey) {
        return extractClaim(token, Claims::getExpiration, publicKey);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, PublicKey publicKey) {
        final Claims claims = extractAllClaims(token, publicKey);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token, PublicKey publicKey) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token,PublicKey publicKey) {
        return extractExpiration(token,publicKey).before(new Date());
    }

    public String generateToken(UserDetails userDetails, PrivateKey privateKey) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername(),privateKey);
    }

    private String createToken(Map<String, Object> claims, String subject, PrivateKey privateKey) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.RS512, privateKey).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails, PublicKey publicKey) {
        final String username = extractUsername(token, publicKey);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token,publicKey));
    }
}