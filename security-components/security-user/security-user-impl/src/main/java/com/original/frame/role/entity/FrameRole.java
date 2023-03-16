package com.original.frame.role.entity;

import lombok.Getter;

import javax.persistence.*;

@Entity
@Table(name = "frame_role")
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Getter
public class FrameRole {

    @Id
    @Column(name = "roleguid")
    private String roleguid;

    @Column(name = "rolename")
    private String rolename;

    @Column(name = "roletype")
    private String roletype;

}
