package com.commerceplatform.api.gateway.security.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class JwtService {
    private static final String SECRET_KEY = "$2a$12$yK6MT6MH.ALvfRt/t1/Qd.0f6GpWUQvNlfrh06ruzOIMIPm1D4qoe";

    public String getSubject(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET_KEY))
            .build()
            .verify(token)
            .getSubject();
    }

    public Map<String, Claim> getClaimsFromToken(String token) {
        DecodedJWT decodedJWT = JWT.decode(token);
        return decodedJWT.getClaims();
    }
}
