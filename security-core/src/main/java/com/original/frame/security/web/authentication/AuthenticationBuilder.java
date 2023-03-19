package com.original.frame.security.web.authentication;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthenticationBuilder {

    Authentication build(HttpServletRequest request, HttpServletResponse response);
}
