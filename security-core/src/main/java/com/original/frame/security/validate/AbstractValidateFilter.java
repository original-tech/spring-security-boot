package com.original.frame.security.validate;

import com.original.frame.security.exception.ValidateCodeException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

public abstract class AbstractValidateFilter extends OncePerRequestFilter {

    protected final SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    protected final AuthenticationFailureHandler authenticationFailureHandler;

    public AbstractValidateFilter(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public void validateCode(ServletWebRequest servletWebRequest, ValidateCode validateCode, String code) {
        if (StringUtils.isBlank(code)) {
            throw new ValidateCodeException("验证码不能为空！");
        }
        if (validateCode == null) {
            throw new ValidateCodeException("验证码不存在！");
        }
        if (validateCode.isExpire()) {
            sessionStrategy.removeAttribute(servletWebRequest, ValidateController.SESSION_KEY_IMAGE_CODE);
            throw new ValidateCodeException("验证码已过期！");
        }
        if (!StringUtils.equalsIgnoreCase(validateCode.getCode(), code)) {
            throw new ValidateCodeException("验证码不正确！");
        }
        sessionStrategy.removeAttribute(servletWebRequest, ValidateController.SESSION_KEY_IMAGE_CODE);
    }
}
