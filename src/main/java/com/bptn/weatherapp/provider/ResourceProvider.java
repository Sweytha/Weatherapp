package com.bptn.weatherapp.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import com.bptn.weatherapp.provider.factory.YamlPropertySourceFactory;

@Component
@PropertySource(value = "classpath:config.yml", factory = YamlPropertySourceFactory.class)
public class ResourceProvider {
	
	@Value("${jwt.secret}")
	private String jwtSecret;

	@Value("${jwt.expiration}")
	private long jwtExpiration;

	@Value("${jwt.issuer}")
	private String jwtIssuer;
		
	@Value("${jwt.audience}")
	private String jwtAudience;

	@Value("${jwt.prefix}")
	private String jwtPrefix;

	@Value("${jwt.excluded.urls}")
	private String[] jwtExcludedUrls;

	@Value("${api.key}")
	private String apiKey;

	@Value("${api.base.url}")
	private String apiBaseUrl;

	@Value("${client.url}")
	private String clientUrl;
	    
	@Value("${client.email.verify.param}")
	private String clientVerifyParam;

	@Value("${client.email.verify.expiration}")
	private long clientVerifyExpiration;
	    
	@Value("${client.email.reset.param}")
	private String clientResetParam;

	@Value("${client.email.reset.expiration}")
	private long clientResetExpiration;

	@Value("${spring.jackson.time-zone}")
	private String timeZone;

	@Value("${spring.jackson.date-format}")
	private String dateFormat;

	@Value("${h2.server.params}")
	private String[] h2ServerParams;

	public String getJwtSecret() {
		return jwtSecret;
	}

	public long getJwtExpiration() {
		return jwtExpiration;
	}

	public String getJwtIssuer() {
		return jwtIssuer;
	}

	public String getJwtAudience() {
		return jwtAudience;
	}

	public String getJwtPrefix() {
		return jwtPrefix;
	}

	public String[] getJwtExcludedUrls() {
		return jwtExcludedUrls;
	}

	public String getApiKey() {
		return apiKey;
	}

	public String getApiBaseUrl() {
		return apiBaseUrl;
	}

	public String getClientUrl() {
		return clientUrl;
	}

	public String getClientVerifyParam() {
		return clientVerifyParam;
	}

	public long getClientVerifyExpiration() {
		return clientVerifyExpiration;
	}

	public String getClientResetParam() {
		return clientResetParam;
	}

	public long getClientResetExpiration() {
		return clientResetExpiration;
	}

	public String getTimeZone() {
		return timeZone;
	}

	public String getDateFormat() {
		return dateFormat;
	}

	public String[] getH2ServerParams() {
		return h2ServerParams;
	}
	
	
}
