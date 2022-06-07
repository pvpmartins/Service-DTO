package br.com.senai.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import br.com.senai.dto.EnderecoDTO;
import br.com.senai.model.Endereco;
import br.com.senai.repository.EnderecoRepository;

@Service
public class EnderecoService {
	@Autowired
	private EnderecoRepository enderecoRepository;

	public EnderecoDTO buscar(String cep) { 
		Optional<Endereco> endereco = enderecoRepository.findByCep(cep);
		if (endereco.isPresent()) {
			return new EnderecoDTO(endereco.get());
		} else {
			RestTemplate rs = new RestTemplate();
			String url = "https://viacep.com.br/ws/" + cep + "/json/";
			Optional<Endereco> enderecoViaCep = Optional.ofNullable(rs.getForObject(url, Endereco.class));
			if (!enderecoViaCep.get().getCep().isEmpty()) {
				String cepSemTraco = enderecoViaCep.get().getCep().replaceAll("-", "");
				enderecoViaCep.get().setCep(cepSemTraco);
				return inserir(enderecoViaCep.get());
			} else {
				return null;
			}

		}
	}

	private EnderecoDTO inserir(Endereco endereco) {
		endereco = enderecoRepository.save(endereco);
		return new EnderecoDTO(endereco);
	}
}
