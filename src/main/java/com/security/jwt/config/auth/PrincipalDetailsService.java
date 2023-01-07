package com.security.jwt.config.auth;

import com.security.jwt.model.UserEntity;
import com.security.jwt.repository.UserEntityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login + (POST) 요청시 동작
// 시큐리티의 기본 로그인 주소는 /login
@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserEntityRepository userEntityRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("loadUserByUsername");
        UserEntity userEntity = userEntityRepository.findByUsername(username).get();
        return new PrincipalDetails(userEntity);
    }
}
