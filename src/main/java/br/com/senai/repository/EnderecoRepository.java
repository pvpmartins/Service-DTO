package br.com.senai.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.senai.model.Endereco;

public interface EnderecoRepository extends JpaRepository<Endereco, Long> {
	Optional<Endereco> findByCep(String cep);
}
