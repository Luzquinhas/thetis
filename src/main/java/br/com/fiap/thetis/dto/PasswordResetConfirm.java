package br.com.fiap.thetis.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

public record PasswordResetConfirm(
        UUID token,
        @NotBlank String newPassword
) {}