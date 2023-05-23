package com.rahma.ville_pays.Security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private PasswordEncoder passwordEncoder;
 @Override
 protected void configure(AuthenticationManagerBuilder auth) throws Exception {
 
	  auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder.encode("123")).roles("ADMIN");
	  auth.inMemoryAuthentication().withUser("Rahma").password(passwordEncoder.encode("123")).roles("AGENT","USER");
	  auth.inMemoryAuthentication().withUser("user1").password(passwordEncoder.encode("123")).roles("USER");
 }
 
 @Override
 protected void configure(HttpSecurity http) throws Exception {
	 http.authorizeRequests().antMatchers("/showCreate").hasAnyRole("ADMIN","AGENT");
	 http.authorizeRequests().antMatchers("/saveVille").hasAnyRole("ADMIN","AGENT");
	 http.authorizeRequests().antMatchers("/ListeVille")
	 .hasAnyRole("ADMIN","AGENT","USER");
	 
	 http.authorizeRequests()
	 .antMatchers("/supprimerVille","/modifierVille","/updateVille")
	 .hasAnyRole("ADMIN");

	 http.authorizeRequests().anyRequest().authenticated();
	 http.formLogin().defaultSuccessUrl("/ListeVille");;
	 http.exceptionHandling().accessDeniedPage("/accessDenied");
 }

}
