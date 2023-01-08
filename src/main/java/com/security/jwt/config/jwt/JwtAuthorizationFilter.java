package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.UserEntity;
import com.security.jwt.repository.UserEntityRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 필터를 가지고 있는데 필터중에 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않는다.
// join 할때에도 JwtAuthorizationFilter 필터를 거치게 된다. permitAll() 해도 의미없다.
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserEntityRepository userEntityRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserEntityRepository userEntityRepository) {
        super(authenticationManager);
        this.userEntityRepository = userEntityRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("JwtAuthorizationFilter 작동");

        //헤더값 확인
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("jwtHeader={}", header);

        // JWT 토큰을 검증을 해서 정상적인 사용자 확인
        if (header == null || !header.startsWith("Bearer ")) {
            log.error("Error occurs while getting header. header is null or invalid");
            chain.doFilter(request, response);
            return;
        }

        String token = header.split(" ")[1].trim();
        log.info("token={}", token);

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(token).getClaim("username").asString();
        log.info("username={}", username); // asString=>aa, toString()=>"aa"

        //서명이 정상적으로 됨
        if (username != null) {
            UserEntity userEntity = userEntityRepository.findByUsername(username).get();
            log.info("user info = {}", userEntity);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //실제로 로그인을 통해 만든 Authentication 가 아니라 토큰 서명을 통해 강제로 생성
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }
}
