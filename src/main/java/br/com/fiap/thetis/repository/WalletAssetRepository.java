package br.com.fiap.thetis.repository;

import br.com.fiap.thetis.model.WalletAsset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface WalletAssetRepository extends JpaRepository<WalletAsset, UUID> {

    List<WalletAsset> findByWalletId(UUID walletId);
}