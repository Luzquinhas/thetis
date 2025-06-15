package br.com.fiap.thetis.service;

import br.com.fiap.thetis.dto.AssetNewsRequest;
import br.com.fiap.thetis.model.Asset;
import br.com.fiap.thetis.model.AssetNews;
import br.com.fiap.thetis.model.AssetSentiment;
import br.com.fiap.thetis.repository.AssetNewsRepository;
import br.com.fiap.thetis.repository.AssetRepository;
import br.com.fiap.thetis.repository.AssetSentimentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AssetNewsService {

    private final AssetRepository assetRepo;
    private final AssetNewsRepository newsRepo;
    private final AssetSentimentRepository sentimentRepo;
    private final ChatBotService chatBot;

    @Transactional
    public void uploadAndAnalyze(AssetNewsRequest req) {
        Asset asset = assetRepo.findById(req.getAssetId())
                .orElseThrow(() -> new IllegalArgumentException("Ativo não encontrado"));

        AssetNews news = AssetNews.builder()
                .asset(asset)
                .title(req.getTitle())
                .summary(req.getSummary())
                .url(req.getUrl())
                .publishedAt(LocalDate.now())
                .build();

        newsRepo.save(news);

        String analysisText = chatBot.processMessage("Analise o sentimento da seguinte notícia: " + req.getSummary()).getMessage();

        String sentiment;
        float confidence = 0.8f; // Pode ser estimado melhor com LLM + regex

        if (analysisText.toLowerCase().contains("positivo")) {
            sentiment = "Positivo";
        } else if (analysisText.toLowerCase().contains("negativo")) {
            sentiment = "Negativo";
        } else {
            sentiment = "Neutro";
        }

        AssetSentiment sentimentEntity = AssetSentiment.builder()
                .asset(asset)
                .sentiment(sentiment)
                .confidenceScore(confidence)
                .analyzedAt(LocalDateTime.now())
                .build();

        sentimentRepo.save(sentimentEntity);
    }
}
