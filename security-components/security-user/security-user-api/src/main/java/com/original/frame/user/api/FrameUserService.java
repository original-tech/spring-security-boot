package com.original.frame.user.api;

import com.original.frame.role.vo.UserRoleVO;
import com.original.frame.user.vo.UserVO;
import org.springframework.cloud.openfeign.FeignClient;

import java.util.List;

@FeignClient(name = "security-user-service")
public interface FrameUserService {

    UserVO findByUsername(String username);

    UserVO findByUsernameOrMobile(String username, String mobile);

    List<UserRoleVO> findRoleByUserguid(String userguid);
}
