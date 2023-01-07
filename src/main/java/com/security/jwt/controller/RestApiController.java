package com.security.jwt.controller;

import com.security.jwt.model.UserEntity;
import com.security.jwt.model.UserRole;
import com.security.jwt.repository.UserEntityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class RestApiController {

    private final UserEntityRepository userEntityRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    //정상적인 토큰(cos) 가 들어와야 들어올 수 있다.
    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody UserEntity user) {
        String encPassword = bCryptPasswordEncoder.encode(user.getPassword());

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(user.getUsername());
        userEntity.setPassword(encPassword);
        userEntity.setRole(UserRole.ROLE_USER);
        userEntityRepository.save(userEntity);
        return "SAVED";
    }
}
