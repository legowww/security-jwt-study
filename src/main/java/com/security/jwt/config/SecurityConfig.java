package com.security.jwt.config;

import com.security.jwt.config.jwt.JwtAuthenticationFilter;
import com.security.jwt.filter.Filter1;
import com.security.jwt.filter.Filter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다.
                .and()
                .formLogin().disable() //내가 form 태그를 만들어서 로그인하는 것을 사용하지 않겠다. disabled 하면 "/login" 경로가 작동안되서 강제로 작동시켜야한다.
                .httpBasic().disable() //Http Basic (매 요청시마다 id,password 를 헤더에 담고 가는것 -> 암호화 문제가 때문에 Https 탄생 )
                .apply(new MyCustomDsl()) // 커스텀 필터 등록
                .and()
                .authorizeRequests(auth -> auth
                        .mvcMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .mvcMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .mvcMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll()
                )
                .build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilterBefore(new Filter3(), SecurityContextHolderFilter.class)
                    .addFilter(corsFilter) //모든 요청이 이 필터를 거치며, cors 정책에서 벗어날 수 있다.
                    .addFilter(new JwtAuthenticationFilter(authenticationManager)); //이걸 추가하면 /login 작동함
        }
    }
}
