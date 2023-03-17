package com.original.frame.user.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "frame_user")
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Getter
@Setter
public class FrameUser {

    @Id
    @Column(name = "userguid")
    private String userguid;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "displayname")
    private String displayname;

    @Column(name = "ouguid")
    private String ouguid;

    @Column(name = "sex")
    private String sex;

    @Column(name = "mobile")
    private String mobile;
}
