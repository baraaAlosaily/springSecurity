package com.example.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserService implements UserDetailsService {

    private final ApplicatioUserDAO applicatioUserDAO;

    @Autowired
    public ApplicationUserService(@Qualifier("fake") ApplicatioUserDAO applicatioUserDAO) {
        this.applicatioUserDAO = applicatioUserDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return applicatioUserDAO.selectApplicationUserByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException(String.format("Username %s not found",username)));
    }
}
