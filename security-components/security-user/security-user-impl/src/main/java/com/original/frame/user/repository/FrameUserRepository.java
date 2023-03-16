package com.original.frame.user.repository;

import com.original.frame.user.entity.FrameUser;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface FrameUserRepository extends PagingAndSortingRepository<FrameUser, String> {

    Optional<FrameUser> findByUsername(String username);

    Optional<FrameUser> findByUsernameOrMobile(String username, String mobile);
}
