package com.example.security.auth;

import java.util.Optional;

public interface ApplicatioUserDAO {
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
