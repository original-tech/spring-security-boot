package com.original.frame.security.handler;

import com.original.frame.core.Response;
import com.original.frame.security.userdetails.FrameUserDetails;
import com.original.frame.security.userdetails.LoginResultVO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FrameAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private final ObjectMapper mapper;

    public FrameAuthenticationSuccessHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        FrameUserDetails userDetails = (FrameUserDetails) authentication.getPrincipal();
        LoginResultVO loginResultVO = new LoginResultVO();
        loginResultVO.setUserId(userDetails.getUsername());
        loginResultVO.setToken("");
        loginResultVO.setRole(null);
        response.getWriter().write(mapper.writeValueAsString(Response.successBuilder(loginResultVO).build()));
    }
}
