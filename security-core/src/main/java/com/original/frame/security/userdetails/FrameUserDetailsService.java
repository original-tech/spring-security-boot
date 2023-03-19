package com.original.frame.security.userdetails;

import com.original.frame.role.entity.FrameRole;
import com.original.frame.role.vo.UserRoleVO;
import com.original.frame.user.api.FrameUserService;
import com.original.frame.user.entity.FrameUser;
import com.original.frame.user.vo.UserVO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.stream.Collectors;

public class FrameUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    private final FrameUserService frameUserService;

    public FrameUserDetailsService(FrameUserService frameUserService,
                                   PasswordEncoder passwordEncoder) {
        this.frameUserService = frameUserService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserVO frameUser = frameUserService.findByUsernameOrMobile(username, username);
        if (frameUser == null) {
            throw new UsernameNotFoundException("该用户不存在");
        }
        List<UserRoleVO> list = frameUserService.findRoleByUserguid(frameUser.getUserguid());

//        List<UserRoleVO> roles = new ArrayList<>();
//        list.forEach(p -> {
//            UserRoleVO roleVO = new UserRoleVO();
//            roleVO.setRoleName(p.getRolename());
//            roleVO.setValue(p.getRoleguid());
//            roles.add(roleVO);
//        });
        // 角色名称的集合
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(list.stream()
                .map(UserRoleVO::getRolename).collect(Collectors.joining(",")));
        return new FrameUserDetails(frameUser.getUsername(), this.passwordEncoder.encode(frameUser.getPassword()),
                true, true, true, true, authorities, "320582");
//        return new UserVO("", frameUser.getUsername(), "", frameUser.getUserguid(), frameUser.getUsername(),
//                "avatar: https://q1.qlogo.cn/g?b=qq&nk=190848757&s=640",
//                this.passwordEncoder.encode(frameUser.getPassword()), "/dashboard/analysis", roles);
    }
}
