package com.original.frame.config.api;

import com.original.frame.config.vo.ConfigVO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "security-config-service", contextId = "frameconfigservice")
public interface FrameConfigService {

    @PostMapping("/findByConfigname")
    ConfigVO findByConfigname(@RequestParam("configname") String configname);
}
