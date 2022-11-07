package com.example.auth.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@EnableWebSecurity
@Configuration
public class AuthSecurityConfig {

	//Configurando a SecurityFilterChain
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	@Bean
	public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated();
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	//Criando o RegisteredClientRepository para guardar os Clients do OAuth2
	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
		
		RegisteredClient awuserClient = RegisteredClient
				.withId(UUID.randomUUID().toString())
				.clientId("awuser")
				.clientSecret(passwordEncoder.encode("123456"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("users:read")
				.scope("users:write")
				.tokenSettings(
					TokenSettings.builder()
					.accessTokenTimeToLive(Duration.ofMinutes(5))
					.build())
				.clientSettings(
					ClientSettings.builder()
					.requireAuthorizationConsent(false)
					.build())
				.build();
		return new InMemoryRegisteredClientRepository(Arrays.asList(awuserClient));
	}
	
	//Configurando o ProviderSettings para declarar quem assina o Token JWT
	@Bean
	public ProviderSettings providerSettings(AuthProperties authProperties) {
		return ProviderSettings.builder()
				.issuer(authProperties.getProviderUri())
				.build();
	}
	
	//JWK para assinar o Token JWT
	@Bean
	public JWKSet jwkSet(AuthProperties authProperties) throws Exception {
		final String jksPath = authProperties.getJks().getPath();
		final String storePass = authProperties.getJks().getStorepass();
		final String alias = authProperties.getJks().getAlias();
		final String keyPass = authProperties.getJks().getKeypass();
		
		final InputStream inputStream = new ClassPathResource(jksPath).getInputStream();
		
		final KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(inputStream, storePass.toCharArray());
		
		RSAKey rsaKey = RSAKey.load(keyStore, alias, keyPass.toCharArray());
		
		return new JWKSet(rsaKey);
	}
	
	//Ajudar a gerenciar o jwkset pra escolher a chave correta
	@Bean
	public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
		return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
	
	
	
}
