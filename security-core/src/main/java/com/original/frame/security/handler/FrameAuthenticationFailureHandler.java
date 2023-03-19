package com.original.frame.security.handler;

import com.original.frame.core.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FrameAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper mapper;

    public FrameAuthenticationFailureHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        response.setContentType("application/json;charset=utf-8");
        if (exception instanceof BadCredentialsException) {
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write(mapper.writeValueAsString(Response.errorBuilder().msg(exception.getMessage()).build()));
        } else {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.getWriter().write(mapper.writeValueAsString(exception.getMessage()));
        }
    }
}
