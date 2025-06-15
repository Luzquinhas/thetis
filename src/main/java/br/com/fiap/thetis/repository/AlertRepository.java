package br.com.fiap.thetis.repository;

import br.com.fiap.thetis.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AlertRepository extends JpaRepository<Alert, UUID> {

    List<Alert> findByUserIdAndIsActiveTrue(UUID userId);

    List<Alert> findByAssetIdAndIsActiveTrue(UUID assetId);
}