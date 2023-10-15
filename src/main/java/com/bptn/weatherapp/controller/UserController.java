package com.bptn.weatherapp.controller;

import static org.springframework.http.HttpStatus.OK;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bptn.weatherapp.jpa.User;
import com.bptn.weatherapp.service.UserService;

@CrossOrigin(exposedHeaders = "Authorization")
@RestController
@RequestMapping("/user")
public class UserController {
    
	final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	UserService userService;
	
	@PostMapping("/signup")
	public User signup(@RequestBody User user) {
		
		logger.debug("Signing up, username: {}", user.getUsername());
		
		return this.userService.signup(user);
	}
	
	@GetMapping("/verify/email")
	public void verifyEmail() {
		
		logger.debug("Verifying Email");
		
		this.userService.verifyEmail();
	}
	
	@PostMapping("/login")
	public ResponseEntity<User> login(@RequestBody User user) {
	
		logger.debug("Authenticating, username: {}, password: {}", user.getUsername(), user.getPassword());
		
		/* Spring Security Authentication. */
		user = this.userService.authenticate(user);

		/* Generate JWT and HTTP Header */
		HttpHeaders jwtHeader = this.userService.generateJwtHeader(user.getUsername());
				
		logger.debug("User Authenticated, username: {}", user.getUsername());
		
		return new ResponseEntity<>(user, jwtHeader, OK);
	}
	
	@GetMapping("/reset/{emailId}")
	public void sendResetPasswordEmail(@PathVariable String emailId) {
		
		logger.debug("Sending Reset Password Email, emailId: {}", emailId);
		
		this.userService.sendResetPasswordEmail(emailId);
	}
	
	@PostMapping("/reset")
	public void passwordReset(@RequestParam String password) {
		
		logger.debug("Resetting Password, password: {}", password);
		
		this.userService.resetPassword(password);
	}
}
