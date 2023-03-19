package com.original.frame.security.validate;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;

@Setter
@Getter
//@Builder
public class ValidateCode implements Serializable {

    private static final long serialVersionUID = -1L;

    private String code;

    private LocalDateTime expireTime;

    public boolean isExpire() {
        return LocalDateTime.now().isAfter(expireTime);
    }

    public ValidateCode(String code, int expireIn) {
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    public ValidateCode(String code, LocalDateTime expireTime) {
        this.code = code;
        this.expireTime = expireTime;
    }
}
