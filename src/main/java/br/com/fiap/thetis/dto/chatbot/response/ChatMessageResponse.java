package br.com.fiap.thetis.dto.chatbot.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ChatMessageResponse {
    private String message;
    private boolean success;
}