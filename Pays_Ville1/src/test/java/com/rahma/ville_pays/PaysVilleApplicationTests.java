package com.rahma.ville_pays;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.test.context.ContextConfiguration;

import com.rahma.ville_pays.entities.ville;
import com.rahma.ville_pays.repos.VillePaysRepository;
import com.rahma.ville_pays.service.VillePaysService;


@ContextConfiguration(classes = ville.class)
@SpringBootTest
class PaysVilleApplicationTests {

	@Autowired
	private VillePaysRepository villeRepository;
	
	@Autowired
	private VillePaysService villeService;
	/* INSERT */
	
		@Test
		public void testCreateVille() 
		{
			ville ville = new ville(null,101L,"Maamoura",8013,new Date());
			villeRepository.save(ville);
		}
		
	/* FIND */ 
		
		@Test
		public void testFindVille()
		{ 
			ville ville = villeRepository.findById(1L).get(); 
			System.out.println(ville);
		}
		
	/* UPDATE */
	
		@Test
		public void testUpdatePopulation()
		{ 
			ville v = villeRepository.findById(1L).get(); 
		
			villeRepository.save(v);
			System.out.println(v);
		}
		
	/* DELETE */
	
	@Test
	public void testDeleteVille()
	{ 
		villeRepository.deleteById(1L); 
		
	}
	
	
	/* FIND_ALL */
	
	@Test
	public void testFindAllProduits()
	{ 
		List<ville> ville =villeRepository.findAll(); 
		for(ville v:ville)
			System.out.println(v);
	}
	
	
	/*Par Page */
	@Test
	public void testFindByNomProduitContains()
	{
	Page<ville> prods = villeService.getAllVillesParPage(0,2);
	System.out.println(prods.getSize());
	System.out.println(prods.getTotalElements());
	System.out.println(prods.getTotalPages());
	prods.getContent().forEach(p -> {System.out.println(p.toString());
	});
	/*ou bien
	for (Produit p : prods.getContent())
	{
	System.out.println(p);
	} */
	}

}
