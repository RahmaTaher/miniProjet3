package com.rahma.ville_pays.controllers;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.rahma.ville_pays.entities.ville;
import com.rahma.ville_pays.service.VillePaysService;

@Controller
public class VillePaysController {
	@Autowired
	VillePaysService villeService;
	
	@GetMapping("/showCreate")
	public String showCreate(ModelMap modelMap) {
		modelMap.addAttribute("ville", new ville());
		modelMap.addAttribute("mode", "new");
		return "createVille";
	}
	
	@PostMapping("/saveVille")
	public String saveVille(@Valid @ModelAttribute("ville") ville ville, BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			return "createVille";
		}
		villeService.saveVille(ville);
		return "redirect:/ListeVille";
	}
	
	@GetMapping("/ListeVille")
	public String listeVille(ModelMap modelMap,
			@RequestParam(name = "page", defaultValue = "0") int page,
			@RequestParam(name = "size", defaultValue = "2") int size) {
		Page<ville> villes = villeService.getAllVillesParPage(page, size);
		modelMap.addAttribute("villes", villes);
		modelMap.addAttribute("pages", new int[villes.getTotalPages()]);
		modelMap.addAttribute("currentPage", page);
		modelMap.addAttribute("size", size);
		return "ListeVille";
	}
	
	@GetMapping("/supprimerVille")
	public String supprimerVille(@RequestParam("id") Long idVille,
			ModelMap modelMap,
			@RequestParam(name = "page", defaultValue = "0") int page,
			@RequestParam(name = "size", defaultValue = "2") int size) {
		villeService.deleteVilleById(idVille);
		return "redirect:/ListeVille?page=" + page + "&size=" + size;
	}
	
	@GetMapping("/modifierVille/{id}")
	public String editerVille(@PathVariable("id") Long idVille, ModelMap modelMap) {
		ville v = villeService.getVille(idVille);
		modelMap.addAttribute("ville", v);
		modelMap.addAttribute("mode", "edit");
		return "createVille";
	}
	
	@PostMapping("/updateVille")
	public String updateVille(@Valid @ModelAttribute("ville") ville ville,
			@RequestParam("date") String date,
			ModelMap modelMap) throws ParseException {
		// Conversion de la date
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		Date dateCreation = dateFormat.parse(date);
		ville.setDateCreation(dateCreation);
		villeService.updateVille(ville);
		return "redirect:/ListeVille";
	}
}
