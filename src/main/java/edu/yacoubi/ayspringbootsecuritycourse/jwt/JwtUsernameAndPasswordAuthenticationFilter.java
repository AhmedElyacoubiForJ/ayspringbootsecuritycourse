package edu.yacoubi.ayspringbootsecuritycourse.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;


public class JwtUsernameAndPasswordAuthenticationFilter
        extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(
            AuthenticationManager authenticationManager,
            JwtConfig jwtConfig,
            SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    // press strg + o to override extended methods
    // to validate credentials
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        try {
            // map credentials from sent request client to java class
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper()
                    .readValue(
                            request.getInputStream(),
                            UsernameAndPasswordAuthenticationRequest.class
                    );

            // map credentials java class to in spring specified interface
            // respectively to the AuthenticationToken technology chosen
            // by the application.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            // validates credentials through spring framework
            Authentication authenticate =
                    authenticationManager.authenticate(authentication);
            return authenticate;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // will be invoked after attemptAuthentication is success
    // create token & sending it to client
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        // create token
        String token = Jwts.builder()
                .setSubject(authResult.getName()) // in our case can be linda, tom or annasmith
                .claim("authorities", authResult.getAuthorities()) // claim is a body
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(
                        LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())
                        )
                )
                .signWith(secretKey)
                .compact();

        // sends token to client
        response.addHeader(
                jwtConfig.getAuthorizationHeader(),
                jwtConfig.getTokenPrefix() + token
        );
    }
}
