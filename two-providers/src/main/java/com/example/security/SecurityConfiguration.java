package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final SecurityProblemSupport problemSupport;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfiguration(SecurityProblemSupport problemSupport, OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler, OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler, CustomOAuth2UserService customOAuth2UserService) {
        this.problemSupport = problemSupport;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
        this.customOAuth2UserService = customOAuth2UserService;
    }

    /*
    By default, Spring OAuth2 uses HttpSessionOAuth2AuthorizationRequestRepository to save
    the authorization request. But, since our service is stateless, we can't save it in
    the session. We'll save the request in a Base64 encoded cookie instead.
  */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(customOAuth2UserService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests(a -> a
                        .antMatchers("/", "/webjars/**", "/auth/**", "/oauth2/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(problemSupport)
                        .accessDeniedHandler(problemSupport)
                )
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )
                .oauth2Login(oauth2Config -> oauth2Config
                        .authorizationEndpoint(oauthEndpointConfig -> oauthEndpointConfig
                                        .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                );
        // @formatter:on

        // Add our custom Token based authentication filter
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
