package com.original.frame.config.controller;

import com.original.frame.config.api.FrameConfigService;
import com.original.frame.config.vo.ConfigVO;
import com.original.frame.core.Response;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ConfigController {

    private final FrameConfigService frameConfigService;

    public ConfigController(@Qualifier("frameConfigServiceImpl") FrameConfigService frameConfigService) {
        this.frameConfigService = frameConfigService;
    }

    @GetMapping(value = "/getConfigValue")
    public Response<?> getConfigValue() {
        ConfigVO configVO = frameConfigService.findByConfigname("systemname");
        return Response.successBuilder(configVO).build();
    }
}
