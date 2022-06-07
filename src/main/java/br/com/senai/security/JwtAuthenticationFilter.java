package br.com.senai.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import br.com.senai.model.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    private JwtUtil jwtUtil;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            try {
                Usuario usuario = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(usuario.getNome(), usuario.getSenha(), new ArrayList<>());
                Authentication auth = authenticationManager.authenticate(authToken);
                return auth;
            }catch (Exception e) {
                throw new RuntimeException("Falha ao autenticar usuario!");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String nome = ((UsuarioDetalhe) authResult.getPrincipal()).getUsername();
        String token = jwtUtil.generateToken(nome);
        response.addHeader("Authorization", "Bearer " + token);
        response.addHeader("access-control-expose-headers", "Authorization");
    }
}
