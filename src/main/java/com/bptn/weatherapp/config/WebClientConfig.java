package com.bptn.weatherapp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import com.bptn.weatherapp.provider.ResourceProvider;

@Configuration
public class WebClientConfig {

	@Autowired
	ResourceProvider provider;

	@Bean
	WebClient webClient(WebClient.Builder builder) {

		return builder.baseUrl(this.provider.getApiBaseUrl()).build();
	}

}