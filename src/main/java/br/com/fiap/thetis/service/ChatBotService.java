package br.com.fiap.thetis.service;

import br.com.fiap.thetis.dto.chatbot.response.ChatMessageResponse;
import br.com.fiap.thetis.dto.chatbot.request.GeminiRequest;
import br.com.fiap.thetis.dto.chatbot.response.GeminiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatBotService {

    @Value("${gemini.api.key}")
    private String geminiApiKey;

    @Value("${gemini.api.url:https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent}")
    private String geminiApiUrl;

    private final RestTemplate restTemplate;

    public ChatMessageResponse processMessage(String userMessage) {
        try {
            String prompt = buildPrompt(userMessage);
            String geminiResponse = callGeminiApi(prompt);
            
            return ChatMessageResponse.builder()
                .message(geminiResponse)
                .success(true)
                .build();
                
        } catch (Exception e) {
            log.error("Erro ao processar mensagem do chatbot: {}", e.getMessage(), e);
            throw new RuntimeException("Erro ao processar mensagem", e);
        }
    }

    private String buildPrompt(String userQuestion) {
        return "Você é um agente virtual do Projeto Thetis, desenvolvido em parceria com a XP. " +
               "Seu papel é auxiliar a pessoa usuária com dúvidas sobre a plataforma Thetis " +
               "(como aplicação de provas, correção, rubricas e funcionalidades) e também sobre " +
               "temas relacionados a investimentos (como tipos de investimentos, perfil de investidor, " +
               "renda fixa, renda variável, entre outros). " +
               "Se a pessoa usuária fizer perguntas fora desses dois temas — Thetis ou investimentos — " +
               "responda educadamente que só pode responder sobre esses assuntos. " +
               "A pessoa usuária perguntou: " + userQuestion;
    }

    private String callGeminiApi(String prompt) {
        String url = geminiApiUrl + "?key=" + geminiApiKey;

        GeminiRequest.Part part = GeminiRequest.Part.builder()
            .text(prompt)
            .build();

        GeminiRequest.Content content = GeminiRequest.Content.builder()
            .parts(List.of(part))
            .build();

        GeminiRequest request = GeminiRequest.builder()
            .contents(List.of(content))
            .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<GeminiRequest> entity = new HttpEntity<>(request, headers);

        try {
            ResponseEntity<GeminiResponse> response = restTemplate.exchange(
                url, 
                HttpMethod.POST, 
                entity, 
                GeminiResponse.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                GeminiResponse geminiResponse = response.getBody();
                
                if (geminiResponse.getCandidates() != null && 
                    !geminiResponse.getCandidates().isEmpty() &&
                    geminiResponse.getCandidates().get(0).getContent() != null &&
                    geminiResponse.getCandidates().get(0).getContent().getParts() != null &&
                    !geminiResponse.getCandidates().get(0).getContent().getParts().isEmpty()) {
                    
                    return geminiResponse.getCandidates().get(0).getContent().getParts().get(0).getText();
                }
            }

            throw new RuntimeException("Resposta inválida da API do Gemini");

        } catch (Exception e) {
            log.error("Erro na chamada para API do Gemini: {}", e.getMessage(), e);
            throw new RuntimeException("Erro ao conectar com a API do Gemini", e);
        }
    }
}