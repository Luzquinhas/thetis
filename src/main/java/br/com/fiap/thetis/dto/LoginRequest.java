package br.com.fiap.thetis.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Username ou email é obrigatório")
        @Size(min = 3, max = 100, message = "Username ou email deve ter entre 3 e 100 caracteres")
        String usernameOrEmail,
        
        @NotBlank(message = "Senha é obrigatória")
        @Size(min = 1, max = 100, message = "Senha deve ter no máximo 100 caracteres")
        String password
) {}
