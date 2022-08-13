package com.bookish.gatewayservice.filter;

import com.bookish.gatewayservice.auth.AuthConstants;
import com.bookish.gatewayservice.auth.JwtAuthService;
import com.bookish.gatewayservice.auth.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.ServletException;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtAuthService jwtAuthService;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);

        String username = null;
        String token = null;

        if (authorizationHeader != null && authorizationHeader.startsWith(AuthConstants.BEARER_TOKEN)) {
            token = authorizationHeader.substring(AuthConstants.BEARER_TOKEN.length());
            username = jwtAuthService.extractUsername(token);
        }


        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtAuthService.validateToken(token, userDetails)) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                // Only continue if we've got a valid token.
                filterChain.doFilter(request, response);
            }
        }
    }
}
