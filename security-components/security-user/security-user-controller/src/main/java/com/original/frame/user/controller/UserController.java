package com.original.frame.user.controller;

import com.original.frame.core.Response;
import com.original.frame.user.api.FrameUserService;
import com.original.frame.user.vo.UserVO;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    private final FrameUserService frameUserService;

    public UserController(FrameUserService frameUserService) {
        this.frameUserService = frameUserService;
    }

    @GetMapping(value = "/getUserInfo")
    public Response<?> getUserInfo() {
        UserVO userVO = frameUserService.findByUsername("admin");
        return Response.successBuilder(userVO).build();
    }
}
