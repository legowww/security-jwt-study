package com.security.jwt.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;


@Entity
@Getter
@Setter
@ToString
public class UserEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private long id;
    private String username;
    private String password;
    @Column(name = "my_role") @Enumerated(EnumType.STRING) private UserRole role;
}
