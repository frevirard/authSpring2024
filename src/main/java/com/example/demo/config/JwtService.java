package com.example.demo.config;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Autowired
    UserDetailsService userdetailDetailsService;

    private String secretKey = "lendysLALAFDELOFHEJFEOFHHDOAHDOSHDHVOJER";
    private Long jwtExpirationTime = (long) 86400000;

    public String generateJwtToken(Authentication authentication) {
        // UserDetailsService userPrincipal =
        // this.userdetailDetailsService.loadUserByUsername);
        System.out.println(new Date((new Date()).getTime()));
        System.out.println("heure actuelle");
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.MINUTE, 60);
        System.out.println(c.getTime());

        return Jwts.builder()
                .subject("admin")
                .issuedAt(new Date())
                .expiration(c.getTime())
                .signWith(getSigningKey())
                .compact();

    }

    // public SecretKey getSigningKey() {
    // byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    // return Keys.hmacShaKeyFor(keyBytes);
    // }

    public SecretKey getSigningKey() {
        byte[] keyBytes = this.secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Extracts the userName from the JWT token.
    // return -> The userName contained in the token.
    public String extractUserName(String token) {
        // Extract and return the subject claim from the token
        return extractClaim(token, Claims::getSubject);
    }

    // Extracts the expiration date from the JWT token.
    // @return The expiration date of the token.
    public Date extractExpiration(String token) {
        // Extract and return the expiration claim from the token
        return extractClaim(token, Claims::getExpiration);
    }

    // Extracts a specific claim from the JWT token.
    // claimResolver A function to extract the claim.
    // return-> The value of the specified claim.
    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        // Extract the specified claim using the provided function
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    // Extracts all claims from the JWT token.
    // return-> Claims object containing all claims.
    private Claims extractAllClaims(String token) {
        // Parse and return all claims from the token
        return Jwts.parser()
                .setSigningKey(getSigningKey())
                .build().parseClaimsJws(token).getBody();
    }

    // Checks if the JWT token is expired.
    // return-> True if the token is expired, false otherwise.
    public Boolean isTokenExpired(String token) {
        // Check if the token's expiration time is before the current time
        return extractExpiration(token).before(new Date());
    }

    // Validates the JWT token against the UserDetails.
    // return-> True if the token is valid, false otherwise.

    public Boolean validateToken(String token, UserDetails userDetails) {
        // Extract username from token and check if it matches UserDetails' username
        final String userName = extractUserName(token);
        // Also check if the token is expired
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
