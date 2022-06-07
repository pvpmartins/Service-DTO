package br.com.senai.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class MailConfig {
	@Autowired
	private JavaMailSender javaMailSender;
	
	
	public void enviarEmail(String para, String assunto, String texto) {
		SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
		simpleMailMessage.setFrom("roni.schanuel@docente.firjan.senai.br");
		simpleMailMessage.setTo(para);
		simpleMailMessage.setSubject(assunto);
		simpleMailMessage.setText("Dados da inscrição do usuário \n\n\n" + texto + "\n\n\n Serratec - Residência - 2022");
		javaMailSender.send(simpleMailMessage);
	}
}
