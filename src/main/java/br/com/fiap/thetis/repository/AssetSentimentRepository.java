package br.com.fiap.thetis.repository;

import br.com.fiap.thetis.model.AssetSentiment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AssetSentimentRepository extends JpaRepository<AssetSentiment, UUID> {

    List<AssetSentiment> findByAssetIdOrderByAnalyzedAtDesc(UUID assetId);
}
