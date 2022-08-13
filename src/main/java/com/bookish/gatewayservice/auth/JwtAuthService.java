package com.bookish.gatewayservice.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthService {
    // TODO: Pull really key from config or properties
    private static final String SECRET_KEY = "supersecretkey";

    private JWTVerifier jwtVerifier;

    private JWTVerifier getJwtVerifier() {
        if (this.jwtVerifier == null) {
            this.jwtVerifier = JWT.require(Algorithm.HMAC512(SECRET_KEY)).build();
        }

        return this.jwtVerifier;
    }

    public String extractUsername(String token) {
        return JWT.decode(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return JWT.decode(token).getExpiresAt();
    }

    public String getRole(String token) {
        return JWT.decode(token).getClaim("role").asString(); // TODO: Add constant here and should probably return a POJO
    }

    private Map<String, Claim> extractAllClaims(String token) {
        return JWT.decode(token).getClaims();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(); // TODO: use real claims
        return createToken(claims, userDetails.getUsername());
    }

    // TODO: Clean this up -> issuer, audience, signing
    private String createToken(Map<String, Object> claims, String subject) {
        return JWT.create().withSubject(subject).withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .withIssuer("bookish-gateway").withPayload(claims)
                .withAudience("services")
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        JWTVerifier verifier = getJwtVerifier();
        verifier.verify(token);

        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
