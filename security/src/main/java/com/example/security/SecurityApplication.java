package com.example.security;

import com.example.security.entity.User1;
import com.example.security.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class SecurityApplication {

	@Autowired
    private UserRepository repository;

	@PostConstruct
	public void initUsers(){
		List<User1> users = Stream.of(
				new User1(101, "mausoof", "123","azam@xyz.com"),
				new User1(102, "asif", "456","asif@xyz.com"),
				new User1(103, "rashid", "789","rashid@xyz.com")
		).collect(Collectors.toList());
		repository.saveAll(users);
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

}
