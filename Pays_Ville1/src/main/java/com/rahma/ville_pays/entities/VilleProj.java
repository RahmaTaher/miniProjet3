package com.rahma.ville_pays.entities;

import org.springframework.data.rest.core.config.Projection;

@Projection(name = "nom", types = { ville.class })
public interface VilleProj {
	public String getNom();

}
