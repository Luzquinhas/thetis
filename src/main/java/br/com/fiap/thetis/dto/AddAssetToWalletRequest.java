package br.com.fiap.thetis.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record AddAssetToWalletRequest(
        @NotNull UUID userId,
        @NotNull UUID assetId
) {}
