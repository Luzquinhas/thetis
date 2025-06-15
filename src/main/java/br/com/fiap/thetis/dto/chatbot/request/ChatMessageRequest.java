package br.com.fiap.thetis.dto.chatbot.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChatMessageRequest {
    
    @NotBlank(message = "Mensagem não pode estar vazia")
    @Size(max = 500, message = "Mensagem não pode ter mais de 500 caracteres")
    private String message;
}