package com.jitendra.springsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

    private String secretKey="";

    public JWTService(){
        try {
            KeyGenerator keyGen= KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk=keyGen.generateKey();
            secretKey= Base64.getEncoder().encodeToString(sk.getEncoded());

        }
        catch (NoSuchAlgorithmException e){
            throw new RuntimeException(e);

        }
    }

    public String generateToken(String username){
        Map<String,Object> claims = new HashMap<>();
        return Jwts
                .builder()

                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))  // 1 hour expiration

                .and()
                .signWith(getKey())
                .compact();
    }


    private SecretKey getKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject); // This is correct, but ensure extractClaim method works properly
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extarctAllClaims(token);  // Fixed the spelling here
        return claimResolver.apply(claims);
    }



    private Claims extarctAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails){
       final String userName = extractUserName(token);
       return (userName.equals(userDetails.getUsername()));

    }

     private boolean isTokenExpired(String token){
        return  extractExpiration(token).before(new Date());
     }

    private Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }











}

