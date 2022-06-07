package br.com.senai.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import br.com.senai.dto.FuncionarioDTO;
import br.com.senai.model.Foto;
import br.com.senai.model.Funcionario;
import br.com.senai.service.FotoService;
import br.com.senai.service.FuncionarioService;

@RestController
@RequestMapping("/funcionarios")
public class FuncionarioController {

	@Autowired
	private FuncionarioService funcionarioService;
	@Autowired
	private FotoService fotoService;

	@GetMapping
	public List<FuncionarioDTO> listar() {
		return funcionarioService.listar();
	}

	@GetMapping("{id}")
	public FuncionarioDTO buscar(@PathVariable Long id) {
		return funcionarioService.buscar(id);
	}

	@GetMapping("/{id}/foto")
	public ResponseEntity<byte[]> buscarPorFoto(@PathVariable Long id) {
		Foto foto = fotoService.buscar(id);
		HttpHeaders headers = new HttpHeaders();
		headers.add("content-type", foto.getTipo());
		headers.add("content-length", String.valueOf(foto.getDados().length));
		return new ResponseEntity<>(foto.getDados(), headers, HttpStatus.OK);
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public FuncionarioDTO inserir(@RequestParam MultipartFile file, @RequestPart Funcionario funcionario)
			throws IOException {
		return funcionarioService.inserir(funcionario, file);
	}

}
