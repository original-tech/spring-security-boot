package com.original.frame.security.userdetails;

import com.original.frame.role.vo.UserRoleVO;
import lombok.Data;

@Data
public class LoginResultVO {
    private String userId;
    private String token;
    private UserRoleVO role;
}
