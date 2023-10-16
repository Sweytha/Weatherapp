package com.bptn.weatherapp.service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.bptn.weatherapp.exception.domain.CityNotFoundException;
import com.bptn.weatherapp.exception.domain.UserNotFoundException;
import com.bptn.weatherapp.jpa.City;
import com.bptn.weatherapp.jpa.Country;
import com.bptn.weatherapp.jpa.User;
import com.bptn.weatherapp.jpa.Weather;
import com.bptn.weatherapp.provider.ResourceProvider;
import com.bptn.weatherapp.repository.CityRepository;
import com.bptn.weatherapp.repository.CountryRepository;
import com.bptn.weatherapp.repository.UserRepository;
import com.bptn.weatherapp.repository.WeatherRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class WeatherService {

	final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	WebClient webClient;

	@Autowired
	ResourceProvider provider;

	@Autowired
	UserRepository userRepository;

	@Autowired
	CityRepository cityRepository;

	@Autowired
	CountryRepository countryRepository;

	@Autowired
	WeatherRepository weatherRepository;
	
	public List<Weather> getWeathers() {
		
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
			
		User user = this.userRepository.findByUsername(username)
	             .orElseThrow(()-> new UserNotFoundException(String.format("Username doesn't exist, %s", username)));
    
		return this.weatherRepository.findFirst10ByUserOrderByWeatherIdDesc(user);
	}

	private String getUri(String city) {

		Map<String, String> map = Map.of("q", city, "units", "metric", "appid", this.provider.getApiKey());

		return "?".concat(map.entrySet().stream().map(e -> String.format("%s=%s", e.getKey(), e.getValue()))
				.collect(Collectors.joining("&")));
	}

	public String getWeatherFromApi(String city) {

		return this.webClient.get().uri(this.getUri(city)).accept(MediaType.APPLICATION_JSON).retrieve()
				.onStatus(status -> HttpStatus.NOT_FOUND.equals(status), response -> {
					throw new CityNotFoundException(String.format("City doesn't exist, %s", city));
				}).bodyToMono(String.class).block();
	}

	private Weather parseWeather(String username, String json) throws JsonMappingException, JsonProcessingException {

		JsonNode rootNode = new ObjectMapper().readTree(json);

		Weather weather = new Weather();

		weather.setWeatherStatusId(rootNode.get("weather").get(0).get("id").asInt());
		weather.setCloudsAll(rootNode.get("clouds").get("all").decimalValue());
		weather.setDescription(rootNode.get("weather").get(0).get("description").asText());
		weather.setFeelsLike(rootNode.get("main").get("feels_like").decimalValue());
		weather.setHumidity(rootNode.get("main").get("humidity").decimalValue());
		weather.setIcon(rootNode.get("weather").get(0).get("icon").asText());
		weather.setPressure(rootNode.get("main").get("pressure").decimalValue());
		weather.setSunrise(new Timestamp(rootNode.get("sys").get("sunrise").asLong() * 1000));
		weather.setSunset(new Timestamp(rootNode.get("sys").get("sunset").asLong() * 1000));
		weather.setTemp(rootNode.get("main").get("temp").decimalValue());
		weather.setTempMax(rootNode.get("main").get("temp_max").decimalValue());
		weather.setTempMin(rootNode.get("main").get("temp_min").decimalValue());
		weather.setVisibility(rootNode.get("visibility").decimalValue());
		weather.setWindDirection(rootNode.get("wind").get("speed").decimalValue());
		weather.setWindSpeed(rootNode.get("wind").get("deg").decimalValue());
		weather.setUpdatedOn(new Timestamp(System.currentTimeMillis()));

		Optional<City> optCity = this.cityRepository.findByWeatherCityId(rootNode.get("id").asInt());

		if (optCity.isEmpty()) {

			City city = new City();

			city.setLatitude(rootNode.get("coord").get("lat").decimalValue());
			city.setLongitude(rootNode.get("coord").get("lon").decimalValue());
			city.setName(rootNode.get("name").asText());
			city.setTimezone(rootNode.get("timezone").asText());
			city.setWeatherCityId(rootNode.get("id").asInt());

			Optional<Country> optCountry = this.countryRepository
					.findByCountryCode(rootNode.get("sys").get("country").asText());

			if (optCountry.isEmpty()) {

				Country country = new Country();

				country.setCountryCode(rootNode.get("sys").get("country").asText());
				country.setCities(new ArrayList<>());
				country.addCity(city);

				this.countryRepository.save(country);
			} else {

				city.setCountry(optCountry.get());
				this.cityRepository.save(city);
			}

			optCity = Optional.of(city);
		}

		weather.setCity(optCity.get());
		weather.setUser(this.userRepository.findByUsername(username).get());

		return weather;
	}

	public Weather getWeather(String city, boolean save) throws JsonMappingException, JsonProcessingException {

		String username = SecurityContextHolder.getContext().getAuthentication().getName();

		String json = this.getWeatherFromApi(city);

		Weather weather = this.parseWeather(username, json);

		if (save) {
			this.weatherRepository.save(weather);
		}

		logger.debug("Weather: {}", weather);

		return weather;
	}
}