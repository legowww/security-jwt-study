package com.security.jwt.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//순환 참조 오류를 해결하기 위해 @Configuration 생성
@Configuration
public class EncoderConfig {
    //리턴되는 오브젝트를 IOC 에 등록해준다.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
