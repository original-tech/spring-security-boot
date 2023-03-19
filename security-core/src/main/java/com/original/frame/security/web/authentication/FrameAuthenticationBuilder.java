package com.original.frame.security.web.authentication;

import com.alibaba.fastjson.JSON;
import com.original.frame.security.userdetails.LoginVO;
import org.apache.commons.io.IOUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FrameAuthenticationBuilder implements AuthenticationBuilder {
    
    @Override
    public Authentication build(HttpServletRequest request, HttpServletResponse response) {
        LoginVO loginVO = JSON.parseObject(getRequestPayload(request), LoginVO.class);
        return new UsernamePasswordAuthenticationToken(
                loginVO.getUsername(), loginVO.getPassword());
    }

    public String getRequestPayload(HttpServletRequest request) {
        try {
            return IOUtils.toString(request.getReader());
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return "";
    }
}
