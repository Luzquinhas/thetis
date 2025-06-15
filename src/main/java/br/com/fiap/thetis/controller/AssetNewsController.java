package br.com.fiap.thetis.controller;

import br.com.fiap.thetis.dto.AssetNewsRequest;
import br.com.fiap.thetis.service.AssetNewsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/news")
@RequiredArgsConstructor
public class AssetNewsController {

    private final AssetNewsService service;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void submitNews(@Valid @RequestBody AssetNewsRequest req) {
        service.uploadAndAnalyze(req);
    }
}
