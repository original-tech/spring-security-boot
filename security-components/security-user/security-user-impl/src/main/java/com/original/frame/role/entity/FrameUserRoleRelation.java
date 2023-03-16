package com.original.frame.role.entity;

import lombok.Getter;

import javax.persistence.*;

@Entity
@Table(name = "frame_userrolerelation")
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Getter
public class FrameUserRoleRelation {

    @Id
    @Column(name = "rowguid")
    private String rowguid;

    @Column(name = "roleguid")
    private String roleguid;

    @Column(name = "userguid")
    private String userguid;
}
