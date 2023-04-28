//package com.commerceplatform.api.gateway.security.utils;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Component;
//
//@Component
//public class JwtUtil {
//
//    @Value("${jwt.secret}")
//    private String jwtSecret;
//
//    @Value("${jwt.token.validity}")
//    private long tokenValidity;
//
//    public void validateToken(final String token) throws JwtTokenMalformedException, JwtTokenMissingException {
//        try {
//            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
//        } catch (SignatureException ex) {
//            throw new JwtTokenMalformedException("Invalid JWT signature");
//        } catch (MalformedJwtException ex) {
//            throw new JwtTokenMalformedException("Invalid JWT token");
//        } catch (ExpiredJwtException ex) {
//            throw new JwtTokenMalformedException("Expired JWT token");
//        } catch (UnsupportedJwtException ex) {
//            throw new JwtTokenMalformedException("Unsupported JWT token");
//        } catch (IllegalArgumentException ex) {
//            throw new JwtTokenMissingException("JWT claims string is empty.");
//        }
//    }
//
//}