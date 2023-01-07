package com.security.jwt.config;

import com.security.jwt.filter.Filter1;
import com.security.jwt.filter.Filter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

//SecurityConfig 필터들이 생성되고 여기 필터들이 실행된다.
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<Filter1> filter1() {
        FilterRegistrationBean<Filter1> bean = new FilterRegistrationBean<>(new Filter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(1); //낮을수록 먼저 실행
        return bean;
    }

    @Bean
    public FilterRegistrationBean<Filter2> filter2() {
        FilterRegistrationBean<Filter2> bean = new FilterRegistrationBean<>(new Filter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); //낮을수록 먼저 실행
        return bean;
    }
}
