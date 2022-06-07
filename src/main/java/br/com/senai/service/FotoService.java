package br.com.senai.service;

import java.io.IOException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import br.com.senai.model.Foto;
import br.com.senai.model.Funcionario;
import br.com.senai.repository.FotoRepository;

@Service
public class FotoService {
	@Autowired
	private FotoRepository fotoRepository;

	public Foto inserir(Funcionario funcionario, MultipartFile file) throws IOException {
		Foto foto = new Foto(null, file.getBytes(), file.getContentType(), file.getName(), funcionario);
		return fotoRepository.save(foto);
	}

	public Foto buscar(Long id) {
		Optional<Foto> foto = fotoRepository.findById(id);
		if (foto.isPresent()) {
			return foto.get();
		}
		return null;
	}
}
