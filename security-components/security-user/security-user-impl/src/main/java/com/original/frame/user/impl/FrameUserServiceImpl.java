package com.original.frame.user.impl;

import com.original.frame.role.entity.FrameRole;
import com.original.frame.role.entity.FrameUserRoleRelation;
import com.original.frame.role.repository.FrameRoleRepository;
import com.original.frame.role.repository.FrameUserRoleRelationRepository;
import com.original.frame.role.vo.UserRoleVO;
import com.original.frame.user.api.FrameUserService;
import com.original.frame.user.entity.FrameUser;
import com.original.frame.user.repository.FrameUserRepository;
import com.original.frame.user.vo.UserVO;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class FrameUserServiceImpl implements FrameUserService {

    private final FrameUserRepository frameUserRepository;
    private final FrameRoleRepository frameRoleRepository;
    private final FrameUserRoleRelationRepository frameUserRoleRelationRepository;

    public FrameUserServiceImpl(FrameUserRepository frameUserRepository,
                                FrameRoleRepository frameRoleRepository,
                                FrameUserRoleRelationRepository frameUserRoleRelationRepository) {
        this.frameUserRepository = frameUserRepository;
        this.frameRoleRepository = frameRoleRepository;
        this.frameUserRoleRelationRepository = frameUserRoleRelationRepository;
    }

    @Override
    public UserVO findByUsername(String username) {
        FrameUser frameUser = frameUserRepository.findByUsername(username).orElse(null);
        if (frameUser == null) {
            return null;
        }
        UserVO userVO = new UserVO();
        BeanUtils.copyProperties(frameUser, userVO);
        return userVO;
    }

    @Override
    public UserVO findByUsernameOrMobile(String username, String mobile) {
        FrameUser frameUser = frameUserRepository.findByUsernameOrMobile(username, mobile).orElse(null);
        if (frameUser == null) {
            return null;
        }
        UserVO userVO = new UserVO();
        BeanUtils.copyProperties(frameUser, userVO);
        return userVO;
    }

    @Override
    public List<UserRoleVO> findRoleByUserguid(String userguid) {
        List<FrameRole> list = new ArrayList<>();
        Iterable<FrameUserRoleRelation> frameUserRoleRelations = frameUserRoleRelationRepository.findByUserguid(userguid);
        frameUserRoleRelations.forEach(p -> frameRoleRepository.findById(p.getRoleguid()).ifPresent(list::add));
        List<UserRoleVO> lst = new ArrayList<>();
        BeanUtils.copyProperties(list, lst);
        return lst;
    }
}
