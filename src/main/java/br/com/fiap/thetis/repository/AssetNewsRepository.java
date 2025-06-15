package br.com.fiap.thetis.repository;

import br.com.fiap.thetis.model.AssetNews;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AssetNewsRepository extends JpaRepository<AssetNews, UUID> {

    List<AssetNews> findByAssetIdOrderByPublishedAtDesc(UUID assetId);
}