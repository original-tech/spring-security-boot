package com.original.frame.config.repository;

import com.original.frame.config.entity.FrameConfig;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface FrameConfigRepository extends PagingAndSortingRepository<FrameConfig, String> {

    Optional<FrameConfig> findByConfigname(String configname);
}
