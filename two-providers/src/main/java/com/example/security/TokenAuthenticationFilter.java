package com.example.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticationFilter.class);
    public static final String TOKEN = "token";
    public static final String PROVIDER = "provider";

    private final CustomOAuth2UserService customOAuth2UserService;

    public TokenAuthenticationFilter(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Map<String, String> params = getParamsFromRequest(request);

            if (StringUtils.hasText(params.get(TOKEN))) {
                UserDetails userDetails = customOAuth2UserService.loadUser(params.get(TOKEN), params.get(PROVIDER));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private Map<String, String> getParamsFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        Map<String, String> values = new HashMap<>();
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            values.put(TOKEN, bearerToken.substring(7));
        }
        String provider = request.getHeader("provider");
        values.put(PROVIDER, provider);
        return values;
    }
}