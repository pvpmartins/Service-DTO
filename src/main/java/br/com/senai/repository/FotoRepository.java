package br.com.senai.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.senai.model.Foto;

public interface FotoRepository extends JpaRepository<Foto, Long> {

}
