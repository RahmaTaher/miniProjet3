 package com.rahma.ville_pays.entities;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

import com.fasterxml.jackson.annotation.JsonIgnore;



@Entity
public class Pays {
	@Id
	@GeneratedValue (strategy = GenerationType.IDENTITY)
	private Long idPays;
	private String nomPays;
	private String capitale; 
	
	
	
	
	@OneToMany (mappedBy = "pays")
	@JsonIgnore
	private List<ville> ville;

	public Pays() {}
	
	
	public Pays(Long idPays, String nomPays, String capitale,
			List<ville> ville) {
		super();
		this.idPays = idPays;
		this.nomPays = nomPays;
		this.capitale = capitale;
		this.ville = ville;
	}

	public Long getIdPays() {
		return idPays;
	}

	public void setIdPays(Long idPays) {
		this.idPays = idPays;
	}

	public String getNomPays() {
		return nomPays;
	}

	public void setNomPays(String nomPays) {
		this.nomPays = nomPays;
	}

	public String getCapitale() {
		return capitale;
	}

	public void setCapitale(String capitale) {
		this.capitale = capitale;
	}

	public List<ville> getVille() {
		return ville;
	}

	public void setVille(List<ville> ville) {
		this.ville = ville;
	}


	@Override
	public String toString() {
		return "Pays [idPays=" + idPays + ", nomPays=" + nomPays + ", capitale=" + capitale + ", ville=" + ville + "]";
	}

	
	
}
