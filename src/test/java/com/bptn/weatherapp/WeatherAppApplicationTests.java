package com.bptn.weatherapp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class WeatherAppApplicationTests {


	@DisplayName("Demo Test")
	@Test
	void contextLoads() {
	}

}
