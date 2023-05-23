package com.rahma.ville_pays.entities;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.PastOrPresent;

import org.springframework.format.annotation.DateTimeFormat;

import groovyjarjarantlr4.v4.runtime.misc.NotNull;

@Entity
public class ville {
	@Id
	@GeneratedValue (strategy = GenerationType.IDENTITY)
	private Long idVille;
		   
		   private Long NumV;
		   
		   @NotNull
		   private String nom;
		   private int codePostal;
		   
		   @Temporal(TemporalType.DATE)
			@DateTimeFormat(pattern = "yyyy-MM-dd")
			@PastOrPresent
		   private Date DateCreation;
		   
		   @ManyToOne
		   private Pays pays;
		   
		public ville(Long idVille, Long numV, String nom, int codePostal, Date dateCreation) {
			super();
			this.idVille = idVille;
			NumV = numV;
			this.nom = nom;
			this.codePostal = codePostal;
			DateCreation = dateCreation;
		}
		
		
		
		public ville() {
			super();
			// TODO Auto-generated constructor stub
		}
		public Long getIdVille() {
			return idVille;
		}
		public void setIdVille(Long idVille) {
			this.idVille = idVille;
		}
		public Long getNumV() {
			return NumV;
		}
		public void setNumV(Long numV) {
			NumV = numV;
		}
		public String getNom() {
			return nom;
		}
		public void setNom(String nom) {
			this.nom = nom;
		}
		public int getCodePostal() {
			return codePostal;
		}
		public void setCodePostal(int codePostal) {
			this.codePostal = codePostal;
		}
		public Date getDateCreation() {
			return DateCreation;
		}
		public void setDateCreation(Date dateCreation) {
			DateCreation = dateCreation;
		}
		@Override
		public String toString() {
			return "ville [idVille=" + idVille + ", NumV=" + NumV + ", nom=" + nom + ", codePostal=" + codePostal
					+ ", DateCreation=" + DateCreation + "]";
		}


	

}
