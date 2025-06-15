package br.com.fiap.thetis.controller;

import br.com.fiap.thetis.dto.chatbot.response.ChatMessageResponse;
import br.com.fiap.thetis.dto.chatbot.request.ChatMessageRequest;
import br.com.fiap.thetis.service.ChatBotService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/chatbot")
@RequiredArgsConstructor
public class ChatBotController {

    private final ChatBotService chatBotService;

    @PostMapping("/message")
    public ResponseEntity<ChatMessageResponse> sendMessage(@Valid @RequestBody ChatMessageRequest request) {
        try {
            ChatMessageResponse response = chatBotService.processMessage(request.getMessage());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            ChatMessageResponse errorResponse = ChatMessageResponse.builder()
                .message("Desculpe, ocorreu um erro ao processar sua mensagem. Tente novamente.")
                .success(false)
                .build();
            return ResponseEntity.ok(errorResponse);
        }
    }
}