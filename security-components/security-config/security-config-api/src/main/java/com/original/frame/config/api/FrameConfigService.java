package com.original.frame.config.api;

import com.original.frame.config.vo.ConfigVO;
import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "security-config-service")
public interface FrameConfigService {

    ConfigVO findByConfigname(String configname);
}
