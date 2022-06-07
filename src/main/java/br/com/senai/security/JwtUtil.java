package br.com.senai.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

//Classe para geracao de token
@Component
public class JwtUtil {
    @Value("${auth.jwt-secret}")
    private String jwtSecret;
    @Value("${auth.jwt-expiration-miliseg}")
    private String jwtExpirationMiliseg;

    public String generateToken(String nome) {
        return Jwts.builder().setSubject(nome)
                .setExpiration(new Date(System.currentTimeMillis() + this.jwtExpirationMiliseg))
                .signWith(SignatureAlgorithm.HS512, this.jwtSecret.getBytes()).compact();
    }

    public boolean isValidToken(String token){
        Claims claims = getClaims(token);
        if(claims != null) {
            String username = claims.getSubject();
            Date expirationDate = claims.getExpiration();
            Date now = new Date(System.currentTimeMillis());
            if(username != null && expirationDate != null && expirationDate.before(expirationDate)) {
                return true;
            }
        }
        return false;
    }

    public Claims getClaims(String token) {
        try{
            return Jwts.parser().setSigningKey(jwtSecret.getBytes()).parseClaimsJws(token).getBody();
        }catch (Exception e) {
            return null;
        }
    }
    public String getUsername(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            return claims.getSubject();
        }
        return null;
    }
}
