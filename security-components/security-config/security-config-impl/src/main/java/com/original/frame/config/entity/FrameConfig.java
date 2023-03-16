package com.original.frame.config.entity;

import lombok.Getter;

import javax.persistence.InheritanceType;
import javax.persistence.*;

@Entity
@Table(name = "frame_config")
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Getter
public class FrameConfig {

    @Id
    @Column(name = "sysguid")
    private String sysguid;

    @Column(name = "configname")
    private String configname;

    @Column(name = "configvalue")
    private String configvalue;

}
