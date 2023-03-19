package com.original.frame.security.userdetails;

import lombok.Data;

@Data
public class LoginVO {
    private String username;
    private String password;
    private boolean goHome;
    private String mode;
}
