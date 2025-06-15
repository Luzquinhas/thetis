package br.com.fiap.thetis.controller;

import br.com.fiap.thetis.dto.AddAssetToWalletRequest;
import br.com.fiap.thetis.model.Asset;
import br.com.fiap.thetis.service.WalletService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;

    @PostMapping("/add")
    public ResponseEntity<String> addAsset(@Valid @RequestBody AddAssetToWalletRequest request) {
        walletService.addAssetToWallet(request);
        return ResponseEntity.ok("Ativo adicionado com sucesso à carteira.");
    }

    @DeleteMapping("/remove/{walletAssetId}")
    public ResponseEntity<String> removeAsset(@PathVariable UUID walletAssetId) {
        walletService.removeAssetFromWallet(walletAssetId);
        return ResponseEntity.ok("Ativo removido com sucesso da carteira.");
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Asset>> listUserAssets(@PathVariable UUID userId) {
        return ResponseEntity.ok(walletService.getAssetsFromWallet(userId));
    }
}