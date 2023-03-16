package com.original.frame.role.repository;

import com.original.frame.role.entity.FrameUserRoleRelation;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface FrameUserRoleRelationRepository extends PagingAndSortingRepository<FrameUserRoleRelation, String> {

    Iterable<FrameUserRoleRelation> findByUserguid(String userguid);

}
