package br.com.fiap.thetis.controller;

import br.com.fiap.thetis.model.AssetNews;
import br.com.fiap.thetis.model.AssetSentiment;
import br.com.fiap.thetis.repository.AssetNewsRepository;
import br.com.fiap.thetis.service.SentimentAnalysisService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/sentiments")
@RequiredArgsConstructor
public class SentimentController {

    private final AssetNewsRepository newsRepo;
    private final SentimentAnalysisService sentimentService;

    @PostMapping("/analyze-news/{newsId}")
    public ResponseEntity<AssetSentiment> analyze(@PathVariable UUID newsId) {
        AssetNews news = newsRepo.findById(newsId)
            .orElseThrow(() -> new IllegalArgumentException("Notícia não encontrada"));
        AssetSentiment sentiment = sentimentService.analyzeNewsSentiment(news);
        return ResponseEntity.ok(sentiment);
    }
}