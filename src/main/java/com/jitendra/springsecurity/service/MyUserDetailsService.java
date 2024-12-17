package com.jitendra.springsecurity.service;

import com.jitendra.springsecurity.model.UserPrincipal;
import com.jitendra.springsecurity.model.Users;
import com.jitendra.springsecurity.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class MyUserDetailsService implements UserDetailsService {

@Autowired
    private UserRepo userRepo;



@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Users user = userRepo.findByUsername(username);

    if (user == null) {
        System.out.println("User not found");
        throw new UsernameNotFoundException("Not found");
    }

    return new UserPrincipal(user);
}













}
