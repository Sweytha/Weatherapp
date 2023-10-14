package com.bptn.weatherapp.jpa;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name="\"City\"")
public class City implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name="\"cityId\"")
	private Integer cityId;

	@Column(precision = 38, scale = 4)
	private BigDecimal latitude;

	@Column(precision = 38, scale = 4)
	private BigDecimal longitude;

	private String name;

	private String timezone;

	@Column(name="\"weatherCityId\"")
	private Integer weatherCityId;

	@ManyToOne
	@JsonManagedReference
	@JoinColumn(name="\"countryId\"")
	private Country country;

	@JsonBackReference
	@OneToMany(mappedBy="city")
	private List<Weather> weathers;

	public Integer getCityId() {
		return cityId;
	}

	public void setCityId(Integer cityId) {
		this.cityId = cityId;
	}

	public BigDecimal getLatitude() {
		return latitude;
	}

	public void setLatitude(BigDecimal latitude) {
		this.latitude = latitude;
	}

	public BigDecimal getLongitude() {
		return longitude;
	}

	public void setLongitude(BigDecimal longitude) {
		this.longitude = longitude;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getTimezone() {
		return timezone;
	}

	public void setTimezone(String timezone) {
		this.timezone = timezone;
	}

	public Integer getWeatherCityId() {
		return weatherCityId;
	}

	public void setWeatherCityId(Integer weatherCityId) {
		this.weatherCityId = weatherCityId;
	}

	public Country getCountry() {
		return country;
	}

	public void setCountry(Country country) {
		this.country = country;
	}

	public List<Weather> getWeathers() {
		return weathers;
	}

	public void setWeathers(List<Weather> weathers) {
		this.weathers = weathers;
	}

	@Override
	public String toString() {
		return "City [cityId=" + cityId + ", latitude=" + latitude + ", longitude=" + longitude + ", name=" + name
				+ ", timezone=" + timezone + ", weatherCityId=" + weatherCityId + ", country=" + country + ", weathers="
				+ weathers + "]";
	}
	
	
	
}