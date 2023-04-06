package com.example.security.repository;

import com.example.security.entity.User1;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User1, Integer> {

    User1 findByUserName(String username);
}
