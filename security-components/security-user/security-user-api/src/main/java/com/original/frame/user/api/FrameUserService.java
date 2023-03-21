package com.original.frame.user.api;

import com.original.frame.role.vo.UserRoleVO;
import com.original.frame.user.vo.UserVO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient(name = "security-user-service", contextId = "frameuserservice", path = "/rest")
public interface FrameUserService {

    @PostMapping(value = "/findByUsername")
    UserVO findByUsername(@RequestParam("username") String username);

    @PostMapping(value = "/findByUsernameOrMobile")
    UserVO findByUsernameOrMobile(@RequestParam("username") String username, @RequestParam("mobile") String mobile);

    @PostMapping(value = "/findRoleByUserguid")
    List<UserRoleVO> findRoleByUserguid(@RequestParam("userguid") String userguid);
}
