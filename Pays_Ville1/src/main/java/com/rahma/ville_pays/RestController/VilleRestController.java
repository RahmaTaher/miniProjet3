package com.rahma.ville_pays.RestController;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.rahma.ville_pays.entities.ville;
import com.rahma.ville_pays.service.VillePaysService;



@RestController
@RequestMapping("/api")
@CrossOrigin
public class VilleRestController {
	@Autowired
	VillePaysService villeService;
	@RequestMapping(method = RequestMethod.GET)
	public List<ville> getAllVilles(@PathVariable("id") Long id) {
	return villeService.getAllVilles();
	}
	@RequestMapping(value="/{id}",method = RequestMethod.GET)
	public ville getVilleById(@PathVariable("id") Long id) {
	return villeService.getVille(id);
	 }
	@RequestMapping(method = RequestMethod.POST)
	public ville createVille(@RequestBody ville ville) {
	return villeService.saveVille(ville);
	}
	@RequestMapping(method = RequestMethod.PUT)
	public ville updateVille (@RequestBody ville ville) {
	return villeService.updateVille(ville);
	}
	@RequestMapping(value="/{id}",method = RequestMethod.DELETE)
	public void deleteVille(@PathVariable("id") Long id)
	{
		villeService.deleteVilleById(id);
	}
	@RequestMapping(value="/Pville/{idPays}",method = RequestMethod.GET)
	public List<ville> getVilleByPaysId(@PathVariable("idPays") Long idPays) {
	return villeService.findByPaysIdPays(idPays);
	}

}
