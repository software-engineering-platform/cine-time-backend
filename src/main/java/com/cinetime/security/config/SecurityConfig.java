package com.cinetime.security.config;

import com.cinetime.security.jwt.AuthEntryPointJwt;
import com.cinetime.security.jwt.JwtAuthenticationFilter;
import com.cinetime.security.jwt.JwtService;
import com.cinetime.security.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.http.HttpMethod;

@EnableWebSecurity
@Configuration
@EnableMethodSecurity(prePostEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final AuthEntryPointJwt authEntryPointJwt;
    private final JwtService jwtService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(authEntryPointJwt)
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(AUTH_WHITELIST).permitAll()
                        .anyRequest().authenticated()
                );

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtService, userDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
            throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        //we let all sources to call our APIs
                        .allowedOrigins("*")
                        .allowedHeaders("*")
                        .allowedMethods("*");
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .build();
    }

    private static final String[] AUTH_WHITELIST = {
            "/actuator/health/**",
            "/api/auth/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/api-docs",
            "/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/webjars/**",
            "/",
            "/index.html",
            "/images/**",
            "/api/images",
            "/api/images/**",
            "/css/**",
            "/js/**",
            "/api/login",
            "/api/google",
            "/api/auth/google",
            "/api/v1/auth/google",
            "/api/cinemas",
            "/api/cinemas/**",
            "/api/cities",
            "/api/cities/**",
            "/api/movies",
            "/api/hall/**",
            "/api/hall",
            "/api/movies/**",
            "/api/special-halls",
            "/api/register",
            "/api/show-times",
            "/api/show-times/**",
            "/api/forgot-password",
            "/api/reset-password",
            "/api/verify-reset-code",
            "/api/reset-password-code",
            "/api/reset-password-direct",
            "/api/contactmessages",
            "/api/contactmessages/**",
            "/error",
            "/api/cinemaimages",
            "/api/cinemaimages/**",
            "/api/favorites/",
            "/api/tickets/buy-ticket",
            "/api/send-email-code",
            "/api/districts",
            "/api/districts/**",
            "/api/countries",
            "/api/countries/**",
            "/api/payment/",
            "/api/payment/**"



    };

}
