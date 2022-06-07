package br.com.senai.service;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.com.senai.dto.FuncionarioDTO;
import br.com.senai.model.Funcionario;
import br.com.senai.repository.FuncionarioRepository;

@Service
public class FuncionarioService {

	@Autowired
	private FuncionarioRepository funcionarioRepository;

	@Autowired
	private FotoService fotoService;

	public List<FuncionarioDTO> listar() {
		List<Funcionario> funcionarios = funcionarioRepository.findAll();
		List<FuncionarioDTO> funcionariosDTO = new ArrayList<>();
		for (Funcionario funcionario : funcionarios) {
			funcionariosDTO.add(inserirURI(funcionario));
		}
		return funcionariosDTO;
	}

	// Método para adicionar o link e retornar o FuncionarioDTO
	public FuncionarioDTO inserirURI(Funcionario funcionario) {
		URI uri = ServletUriComponentsBuilder.fromCurrentContextPath().path("/funcionarios/{id}/foto")
				.buildAndExpand(funcionario.getId()).toUri();
		FuncionarioDTO funcionarioDTO = new FuncionarioDTO();
		funcionarioDTO.setNome(funcionario.getNome());
		funcionarioDTO.setUrl(uri.toString());
		return funcionarioDTO;
	}

	public FuncionarioDTO buscar(Long id) {
		Optional<Funcionario> funcionario = funcionarioRepository.findById(id);
		return inserirURI(funcionario.get());
	}

	//Inserir o Funcionário na tabela e a Foto do funcionário
	public FuncionarioDTO inserir(Funcionario funcionario, MultipartFile file) throws IOException {
		fotoService.inserir(funcionarioRepository.save(funcionario), file);
		return inserirURI(funcionario);
	}

}
