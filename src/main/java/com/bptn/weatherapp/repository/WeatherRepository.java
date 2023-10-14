package com.bptn.weatherapp.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bptn.weatherapp.jpa.User;
import com.bptn.weatherapp.jpa.Weather;

public interface WeatherRepository extends JpaRepository<Weather, Integer> {

	
	List<Weather> findFirst10ByUserOrderByWeatherIdDesc(User user);
}
