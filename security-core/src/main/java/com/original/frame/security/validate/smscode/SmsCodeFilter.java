package com.original.frame.security.validate.smscode;


import com.original.frame.security.exception.ValidateCodeException;
import com.original.frame.security.validate.AbstractValidateFilter;
import com.original.frame.security.validate.ValidateCode;
import com.original.frame.security.validate.ValidateController;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SmsCodeFilter extends AbstractValidateFilter {

    public SmsCodeFilter(AuthenticationFailureHandler authenticationFailureHandler) {
        super(authenticationFailureHandler);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, @NonNull HttpServletResponse httpServletResponse, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        if (StringUtils.equalsIgnoreCase("/login/mobile", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "post")) {
            try {
                ServletWebRequest servletWebRequest = new ServletWebRequest(httpServletRequest);
                String smsCodeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "smsCode");
                String mobileInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "mobile");
                ValidateCode smsCodeInSession = (ValidateCode) sessionStrategy.getAttribute(servletWebRequest, ValidateController.SESSION_KEY_SMS_CODE + mobileInRequest);
                validateCode(servletWebRequest, smsCodeInSession, smsCodeInRequest);
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}