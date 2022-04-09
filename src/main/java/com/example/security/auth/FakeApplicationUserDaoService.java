package com.example.security.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.security.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicatioUserDAO{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUser()
                .stream()
                .filter(applicationUser -> username
                        .equals(applicationUser.getUsername()))
                        .findFirst();
    }

    private List<ApplicationUser> getApplicationUser(){
        List<ApplicationUser> applicationUsers= Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("1234"),
                         "baraa" ,
                        true,
                        true,
                        true,
                        true
                ),    new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("1234"),
                         "linda" ,
                        true,
                        true,
                        true,
                        true
                ),    new ApplicationUser(
                        ADMINTRANEE.getGrantedAuthorities(),
                        passwordEncoder.encode("1234"),
                         "tom" ,
                        true,
                        true,
                        true,
                        true
                )

        );

        return applicationUsers;
    }
}
