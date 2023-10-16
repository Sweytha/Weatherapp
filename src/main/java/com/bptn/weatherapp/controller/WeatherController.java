package com.bptn.weatherapp.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bptn.weatherapp.jpa.Weather;
import com.bptn.weatherapp.service.WeatherService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

@CrossOrigin
@RestController
@RequestMapping("/weathers")
public class WeatherController {
	
	final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	WeatherService weatherService;
	
	@GetMapping("/{city}/{save}")
	public Weather getWeather(@PathVariable String city, @PathVariable boolean save) throws JsonMappingException, JsonProcessingException {
				
		logger.debug("Getting Weather from API, city: {}, save: {}", city, save);
		
		return this.weatherService.getWeather(city, save);	
	}

	
	@GetMapping
	public List<Weather> getWeather() {
		
		logger.debug("Getting Weather List");
		
		return this.weatherService.getWeathers();	
	}
}