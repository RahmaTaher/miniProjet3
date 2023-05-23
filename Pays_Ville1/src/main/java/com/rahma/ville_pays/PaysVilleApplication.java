package com.rahma.ville_pays;




import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

import com.rahma.ville_pays.service.VillePaysService;
import com.rahma.ville_pays.entities.ville;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;



@SpringBootApplication
public class PaysVilleApplication implements CommandLineRunner{
	@Autowired
	VillePaysService villeService;
	@Autowired
	private RepositoryRestConfiguration repositoryRestConfiguration;

	public static void main(String[] args) {
		SpringApplication.run(PaysVilleApplication.class, args);
	}
	@Override
	public void run(String... args) throws Exception {
		
		repositoryRestConfiguration.exposeIdsFor(ville.class);
		
	}
}

