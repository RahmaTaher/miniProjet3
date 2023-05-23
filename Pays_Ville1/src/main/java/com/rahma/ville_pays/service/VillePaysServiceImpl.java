package com.rahma.ville_pays.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.rahma.ville_pays.entities.Pays;
import com.rahma.ville_pays.entities.ville;
import com.rahma.ville_pays.repos.VillePaysRepository;
@Service
public class VillePaysServiceImpl implements VillePaysService{
	@Autowired
	VillePaysRepository villeRepository;

	@Override
	public ville saveVille(ville v) {
		
		return villeRepository.save(v);
	}

	@Override
	public ville updateVille(ville v) {
		return villeRepository.save(v);
	}

	

	@Override
	public void deleteVilleById(Long id) {
		villeRepository.deleteById(id);
		
	}

	@Override
	public ville getVille(Long id) {
		
		return villeRepository.findById(id).get();
	}

	@Override
	public List<ville> getAllVilles() {
		return villeRepository.findAll();
	}

	@Override
	public Page<ville> getAllVillesParPage(int page, int size) {
		
		return villeRepository.findAll(PageRequest.of(page, size));
	}

	@Override
	public void deleteVille(ville v) {
		villeRepository.delete(v);
		
	}

	@Override
	public List<ville> findByPaysIdPays(Long idPays) {
	
		return villeRepository.findByPaysIdPays(idPays);
	}

	@Override
	public List<ville> findByPays(Pays pays) {
		return villeRepository.findByPays(pays);
	}

}
