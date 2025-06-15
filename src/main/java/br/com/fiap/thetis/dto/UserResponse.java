package br.com.fiap.thetis.dto;

import java.util.UUID;

public record UserResponse(
        UUID id,
        String username,
        String email,
        String phone,
        String cpf
) {}
