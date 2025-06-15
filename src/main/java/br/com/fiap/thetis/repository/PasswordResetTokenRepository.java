package br.com.fiap.thetis.repository;

import br.com.fiap.thetis.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {
    Optional<PasswordResetToken> findByIdAndUsedFalseAndExpiresAtAfter(UUID id, java.time.LocalDateTime now);
}