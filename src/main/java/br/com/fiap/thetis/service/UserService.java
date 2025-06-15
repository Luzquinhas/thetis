package br.com.fiap.thetis.service;

import br.com.fiap.thetis.dto.*;
import br.com.fiap.thetis.model.*;
import br.com.fiap.thetis.repository.*;
import br.com.fiap.thetis.util.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.time.LocalDateTime;
import java.util.NoSuchElementException;

@Slf4j
@Service                       // nenhum @Profile → vale para todos os ambientes
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepo;
    private final PasswordResetTokenRepository tokenRepo;
    private final PasswordEncoder encoder;
    private final EmailService email;
    private final EncryptionUtil encryptionUtil;

    /* ---------- Cadastro ---------- */
    @Transactional
    public UserResponse create(CreateUserRequest req) {
        log.info("Tentativa de cadastro para username: {}, email: {}", req.username(), req.email());
        
        try {
            validarDuplicidade(req);
            
            User u = User.builder()
                    .username(req.username())
                    .email(req.email())
                    .passwordHash(encoder.encode(req.password()))
                    .createdAt(LocalDateTime.now())
                    .modifiedAt(LocalDateTime.now())
                    .build();
            
            // Criptografar dados sensíveis
            u.setPhone(req.phone());
            u.setCpf(req.cpf().replaceAll("\\D", ""));
            
            userRepo.save(u);
            
            log.info("Usuário cadastrado com sucesso: {}", u.getId());
            return map(u);
            
        } catch (Exception e) {
            log.error("Erro ao cadastrar usuário - username: {}, email: {}, erro: {}", 
                     req.username(), req.email(), e.getMessage());
            throw e;
        }
    }

    /* ---------- Login ---------- */
    public UserResponse login(LoginRequest req) {
        log.info("Tentativa de login para: {}", req.usernameOrEmail());
        
        try {
            User u = buscarPorUsernameOuEmail(req.usernameOrEmail());
            
            if (!encoder.matches(req.password(), u.getPasswordHash())) {
                log.warn("Tentativa de login com senha inválida para: {}", req.usernameOrEmail());
                throw new IllegalArgumentException("Senha inválida");
            }
            
            log.info("Login realizado com sucesso para usuário: {}", u.getId());
            return map(u);
            
        } catch (Exception e) {
            log.error("Erro no login para: {}, erro: {}", req.usernameOrEmail(), e.getMessage());
            throw e;
        }
    }

    /* ---------- Solicitar reset ---------- */
    @Transactional
    public void requestPasswordReset(PasswordResetRequest req) {
        log.info("Solicitação de reset de senha para email: {}", req.email());
        
        try {
            User u = userRepo.findByEmail(req.email())
                    .orElseThrow(() -> new NoSuchElementException("Usuário não encontrado"));
            
            PasswordResetToken token = PasswordResetToken.builder()
                    .user(u)
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .used(false)
                    .build();
            tokenRepo.save(token);

            String link = "https://thetis.app/reset?token=" + token.getId();
            email.send(u.getEmail(), "Recuperação de senha",
                       "Clique no link para redefinir sua senha:\n" + link);
            
            log.info("Email de reset enviado para: {}", req.email());
            
        } catch (Exception e) {
            log.error("Erro ao solicitar reset de senha para: {}, erro: {}", req.email(), e.getMessage());
            throw e;
        }
    }

    /* ---------- Confirmar reset ---------- */
    @Transactional
    public void confirmPasswordReset(PasswordResetConfirm req) {
        log.info("Confirmação de reset de senha para token: {}", req.token());
        
        try {
            PasswordResetToken token = tokenRepo
                    .findByIdAndUsedFalseAndExpiresAtAfter(req.token(), LocalDateTime.now())
                    .orElseThrow(() -> new IllegalArgumentException("Token inválido ou expirado"));

            User u = token.getUser();
            u.setPasswordHash(encoder.encode(req.newPassword()));
            u.setModifiedAt(LocalDateTime.now());
            token.setUsed(true);
            
            log.info("Senha redefinida com sucesso para usuário: {}", u.getId());
            
        } catch (Exception e) {
            log.error("Erro ao confirmar reset de senha para token: {}, erro: {}", req.token(), e.getMessage());
            throw e;
        }
    }

    /* ---------- Helpers ---------- */
    private void validarDuplicidade(CreateUserRequest req) {
        if (userRepo.findByEmail(req.email()).isPresent()) {
            log.warn("Tentativa de cadastro com email já existente: {}", req.email());
            throw new IllegalArgumentException("E-mail já cadastrado");
        }
        if (userRepo.findByUsername(req.username()).isPresent()) {
            log.warn("Tentativa de cadastro com username já existente: {}", req.username());
            throw new IllegalArgumentException("Username já cadastrado");
        }
    }

    private User buscarPorUsernameOuEmail(String usernameOrEmail) {
        return userRepo.findByEmail(usernameOrEmail)
                       .or(() -> userRepo.findByUsername(usernameOrEmail))
                       .orElseThrow(() -> new NoSuchElementException("Usuário não encontrado"));
    }

    private UserResponse map(User u) {
        return new UserResponse(u.getId(), u.getUsername(),
                                u.getEmail(), u.getPhone(), u.getCpf());
    }
}