package br.com.fiap.thetis.service;

import br.com.fiap.thetis.dto.AddAssetToWalletRequest;
import br.com.fiap.thetis.model.*;
import br.com.fiap.thetis.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class WalletService {

    private final WalletRepository walletRepo;
    private final AssetRepository assetRepo;
    private final UserRepository userRepo;
    private final WalletAssetRepository walletAssetRepo;

    @Transactional
    public void addAssetToWallet(AddAssetToWalletRequest req) {
        User user = userRepo.findById(req.userId())
                .orElseThrow(() -> new NoSuchElementException("Usuário não encontrado"));
        Asset asset = assetRepo.findById(req.assetId())
                .orElseThrow(() -> new NoSuchElementException("Ativo não encontrado"));

        Wallet wallet = walletRepo.findByUserId(user.getId())
                .stream().findFirst()
                .orElseGet(() -> {
                    Wallet newWallet = Wallet.builder().user(user).build();
                    return walletRepo.save(newWallet);
                });

        boolean alreadyExists = wallet.getWalletAssets().stream()
                .anyMatch(wa -> wa.getAsset().getId().equals(asset.getId()));

        if (!alreadyExists) {
            WalletAsset walletAsset = WalletAsset.builder()
                    .wallet(wallet)
                    .asset(asset)
                    .build();
            walletAssetRepo.save(walletAsset);
        }
    }

    @Transactional
    public void removeAssetFromWallet(UUID walletAssetId) {
        walletAssetRepo.deleteById(walletAssetId);
    }

    public List<Asset> getAssetsFromWallet(UUID userId) {
        return walletRepo.findByUserId(userId).stream()
                .flatMap(w -> w.getWalletAssets().stream())
                .map(WalletAsset::getAsset)
                .toList();
    }
}
