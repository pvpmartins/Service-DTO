package br.com.senai.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.senai.model.Funcionario;

public interface FuncionarioRepository extends JpaRepository<Funcionario, Long> {
	Funcionario findByNome(String nome);
}
