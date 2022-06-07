package br.com.senai.repository;


import java.time.LocalDate;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import br.com.senai.model.Vendedor;

public interface VendedorRepository extends JpaRepository<Vendedor, Long> {
	// JPQL- LINGUAGEM DE CONSULTA DO SPRING DATA JPA

	@Query("SELECT v FROM Vendedor v WHERE v.salario>=:valorMinimo AND v.salario<=:valorMaximo")
	Page<Vendedor> buscarSalarioPorFaixa(Double valorMinimo, Double valorMaximo, Pageable pageable);

	Page<Vendedor> findBySalarioBetween(Double valorMinimo, Double valorMaximo, Pageable pageable);

	@Query("SELECT v FROM Vendedor v WHERE UPPER(v.nome) LIKE UPPER(CONCAT('%',:paramNome,'%'))")
	Page<Vendedor> buscarNome(String paramNome, Pageable pageable);

	Page<Vendedor> findByNomeContainingIgnoreCase(String paramNome, Pageable pageable);
	
	Page<Vendedor> findByDataNascimentoGreaterThan(LocalDate dataNascimento, Pageable pageable);

}
