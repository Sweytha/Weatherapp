package com.bptn.weatherapp.service;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bptn.weatherapp.exception.domain.EmailExistException;
import com.bptn.weatherapp.exception.domain.EmailNotVerifiedException;
import com.bptn.weatherapp.exception.domain.UserNotFoundException;
import com.bptn.weatherapp.exception.domain.UsernameExistException;
import com.bptn.weatherapp.jpa.User;
import com.bptn.weatherapp.provider.ResourceProvider;
import com.bptn.weatherapp.repository.UserRepository;
import com.bptn.weatherapp.security.JwtService;

@Service
public class UserService {
	
	final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	EmailService emailService;

	@Autowired
	UserRepository userRepository;

	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	JwtService jwtService;

	@Autowired
	ResourceProvider provider;
	
	public User signup(User user) {

		user.setUsername(user.getUsername().toLowerCase());
		user.setEmailId(user.getEmailId().toLowerCase());

		this.validateUsernameAndEmail(user.getUsername(), user.getEmailId());

		user.setEmailVerified(false);
		user.setPassword(this.passwordEncoder.encode(user.getPassword()));
		user.setCreatedOn(Timestamp.from(Instant.now()));
		this.userRepository.save(user);

		this.emailService.sendVerificationEmail(user);

		return user;
	}
	
	private void validateUsernameAndEmail(String username, String emailId) {

		this.userRepository.findByUsername(username).ifPresent(u -> {
			throw new UsernameExistException(String.format("Username already exists, %s", u.getUsername()));
		});

		this.userRepository.findByEmailId(emailId).ifPresent(u -> {
			throw new EmailExistException(String.format("Email already exists, %s", u.getEmailId()));
		});

	}
	

	public void verifyEmail() {

		String username = SecurityContextHolder.getContext().getAuthentication().getName();

		User user = this.userRepository.findByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(String.format("Username doesn't exist, %s", username)));

		user.setEmailVerified(true);

		this.userRepository.save(user);

	}
	public User authenticate(User user) {

		/* Spring Security Authentication. */
		this.authenticate(user.getUsername(), user.getPassword());

		/* Get User from the DB. */
		return this.userRepository.findByUsername(user.getUsername()).map(UserService::isEmailVerified).get();
	};

	private Authentication authenticate(String username, String password) {
		return this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}

	private static User isEmailVerified(User user) {

		if (user.getEmailVerified().equals(false)) {
			throw new EmailNotVerifiedException(String.format("Email requires verification, %s", user.getEmailId()));
		}

		return user;
	}

	public HttpHeaders generateJwtHeader(String username) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION, this.jwtService.generateJwtToken(username, this.provider.getJwtExpiration()));
		return headers;
	}
	

	public void sendResetPasswordEmail(String emailId) {

		Optional<User> opt = this.userRepository.findByEmailId(emailId);

		if (opt.isPresent()) {
			this.emailService.sendResetPasswordEmail(opt.get());
		} else {
			logger.debug("Email doesn't exist, {}", emailId);
		}
	}
	
	public void resetPassword(String password) {

		String username = SecurityContextHolder.getContext().getAuthentication().getName();

		User user = this.userRepository.findByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(String.format("Username doesn't exist, %s", username)));

		user.setPassword(this.passwordEncoder.encode(password));

		this.userRepository.save(user);
	}

}
