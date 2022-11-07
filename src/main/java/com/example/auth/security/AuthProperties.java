package com.example.auth.security;

import javax.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Validated
@ConfigurationProperties("aw.auth")
public class AuthProperties {

	@NotBlank
	private String providerUri;
	
	private JksProperties jks;

	public String getProviderUri() {
		return providerUri;
	}

	public void setProviderUri(String providerUri) {
		this.providerUri = providerUri;
	}
	
	public JksProperties getJks() {
		return jks;
	}

	public void setJks(JksProperties jks) {
		this.jks = jks;
	}
	
	static class JksProperties {
		
		@NotBlank
		private String keypass;
		
		@NotBlank
		private String storepass;
		
		@NotBlank
		private String alias;
		
		@NotBlank
		private String path;

		public String getKeypass() {
			return keypass;
		}

		public void setKeypass(String keypass) {
			this.keypass = keypass;
		}

		public String getStorepass() {
			return storepass;
		}

		public void setStorepass(String storepass) {
			this.storepass = storepass;
		}

		public String getAlias() {
			return alias;
		}

		public void setAlias(String alias) {
			this.alias = alias;
		}

		public String getPath() {
			return path;
		}

		public void setPath(String path) {
			this.path = path;
		}
		
	}
	
}
