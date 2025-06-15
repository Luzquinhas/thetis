package br.com.fiap.thetis.dto;

import jakarta.validation.constraints.*;
import org.hibernate.validator.constraints.br.CPF;

public record CreateUserRequest(
        @NotBlank(message = "Username é obrigatório")
        @Pattern(regexp = "^[a-zA-Z0-9_]{3,20}$", message = "Username deve conter apenas letras, números e underscore, entre 3 e 20 caracteres")
        String username,
        
        @NotBlank(message = "Email é obrigatório")
        @Email(message = "Email deve ter formato válido")
        String email,
        
        @NotBlank(message = "Telefone é obrigatório")
        @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Telefone deve ter formato válido")
        String phone,
        
        @NotBlank(message = "CPF é obrigatório")
        @CPF(message = "CPF deve ter formato válido")
        String cpf,
        
        @NotBlank(message = "Senha é obrigatória")
        @Size(min = 8, max = 100, message = "Senha deve ter entre 8 e 100 caracteres")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$", 
                message = "Senha deve conter pelo menos: 1 letra minúscula, 1 maiúscula, 1 número e 1 caractere especial")
        String password
) {}
