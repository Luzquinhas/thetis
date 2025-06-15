package br.com.fiap.thetis.service;

import br.com.fiap.thetis.model.AssetNews;
import br.com.fiap.thetis.model.AssetSentiment;
import br.com.fiap.thetis.repository.AssetSentimentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class SentimentAnalysisService {

    private final GeminiService geminiService;
    private final AssetSentimentRepository sentimentRepo;

    public AssetSentiment analyzeNewsSentiment(AssetNews news) {
        String prompt = buildPrompt(news);
        String response = geminiService.gerarConteudo(prompt);

        String sentiment = parseSentiment(response);
        float confidence = parseConfidence(response);

        AssetSentiment result = AssetSentiment.builder()
                .asset(news.getAsset())
                .sentiment(sentiment)
                .confidenceScore(confidence)
                .analyzedAt(LocalDateTime.now())
                .build();

        return sentimentRepo.save(result);
    }

    private String buildPrompt(AssetNews news) {
        return String.format("""
                Analise o sentimento do seguinte texto relacionado ao ativo financeiro "%s":
                
                Título: %s
                Resumo: %s
                
                Classifique o sentimento como POSITIVO, NEUTRO ou NEGATIVO.
                Além disso, forneça uma nota de confiança entre 0 e 100.

                Formato da resposta:
                Sentimento: POSITIVO
                Confiança: 87.5
                """, news.getAsset().getSymbol(), news.getTitle(), news.getSummary());
    }

    private String parseSentiment(String response) {
        String[] lines = response.split("\n");
        for (String line : lines) {
            if (line.toLowerCase().contains("sentimento:")) {
                return line.split(":")[1].trim().toUpperCase();
            }
        }
        return "NEUTRO"; // fallback
    }

    private float parseConfidence(String response) {
        String[] lines = response.split("\n");
        for (String line : lines) {
            if (line.toLowerCase().contains("confiança:")) {
                try {
                    return Float.parseFloat(line.split(":")[1].trim().replace(",", "."));
                } catch (Exception ignored) {}
            }
        }
        return 50.0f; // fallback
    }
}
