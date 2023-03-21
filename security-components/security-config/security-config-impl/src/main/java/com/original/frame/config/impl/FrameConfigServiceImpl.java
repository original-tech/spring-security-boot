package com.original.frame.config.impl;

import com.original.frame.config.api.FrameConfigService;
import com.original.frame.config.entity.FrameConfig;
import com.original.frame.config.repository.FrameConfigRepository;
import com.original.frame.config.vo.ConfigVO;
import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest")
public class FrameConfigServiceImpl implements FrameConfigService {

    private final FrameConfigRepository frameConfigRepository;

    public FrameConfigServiceImpl(FrameConfigRepository frameConfigRepository) {
        this.frameConfigRepository = frameConfigRepository;
    }

    @Override
    public ConfigVO findByConfigname(String configname) {
        FrameConfig frameConfig = frameConfigRepository.findByConfigname(configname).orElse(null);
        if (frameConfig == null) {
            return null;
        }
        ConfigVO configVO = new ConfigVO();
        BeanUtils.copyProperties(frameConfig, configVO);
        return configVO;
    }
}
