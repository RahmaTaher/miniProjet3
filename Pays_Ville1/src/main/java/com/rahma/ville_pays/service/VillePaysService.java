package com.rahma.ville_pays.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.rahma.ville_pays.entities.Pays;
import com.rahma.ville_pays.entities.ville;



public interface VillePaysService {
	ville saveVille(com.rahma.ville_pays.entities.ville ville );
	ville updateVille(ville V);
	
	void deleteVilleById(Long idVille);
	ville getVille(Long idVille);
	List<ville> getAllVilles();
	Page<ville> getAllVillesParPage(int page, int size);
	List<ville> findByPays(Pays pays);
	List<ville> findByPaysIdPays(Long idPays);
	void deleteVille(ville v);
	


}
