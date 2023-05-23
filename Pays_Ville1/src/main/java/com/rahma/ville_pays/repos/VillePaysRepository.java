package com.rahma.ville_pays.repos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;


import com.rahma.ville_pays.entities.Pays;
import com.rahma.ville_pays.entities.ville;


// @RepositoryRestResource(path = "rest")
public interface VillePaysRepository extends JpaRepository<ville,Long>{
	List<ville> findByPays(Pays pays);
	
	List<ville> findByPaysIdPays(Long id);
}
