package com.example.eazybankbackendapplication.service;

import com.example.eazybankbackendapplication.model.Customer;
import com.example.eazybankbackendapplication.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EazyBankUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    /**
     * @param username the username identifying the user whose data is required.
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

       Customer customer = customerRepository.findByEmail(username)
               .orElseThrow(() -> new UsernameNotFoundException("User detail not found for the user: " + username));

        List<GrantedAuthority> authorityList = customer.getAuthorities().stream().map(authority -> new
               SimpleGrantedAuthority(authority.getName())).collect(Collectors.toList());


       return new User(customer.getEmail(), customer.getPwd(), authorityList);
    }
}
