package com.security.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class Filter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //Token: cos
        //cos 토큰을 만들어줘서 id, pw 가 정상적으로 들어와서 로그인이 되면 토큰을 만들어주고 응답을 해준다.
        //요청을 할 때 마다 header/Authorization 를 참고하여 토큰을 가져오겠죠?
        //그떄 토큰이 넘어오면 이 토큰이 서버인 내가 만든 토큰이 맞는지만 검증만 하면 된다.(RSA, HS256)
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            log.info("필터3, {}", headerAuth);

            if(headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            }
            else {
                PrintWriter out = res.getWriter();
                out.write("Authorization fail");
            }
        }
    }
}
