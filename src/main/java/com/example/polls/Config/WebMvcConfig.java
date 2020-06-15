package com.example.polls.Config;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class WebMvcConfig implements WebMvcConfigurer {

    private final long MAX_AGES_SECS = 3600;

    @Override
    public void addCorsmappings(CorsRegistry registry) {
        registry.addMapping("/**")  
                .allowedOrigins("*") 
                .allowedMethods("HEAD", "OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE")
                .maxAge(MAX_AGES_SECS);
    }
    
}