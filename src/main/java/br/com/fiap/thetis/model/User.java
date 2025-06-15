package br.com.fiap.thetis.model;

import br.com.fiap.thetis.util.EncryptionUtil;
import br.com.fiap.thetis.config.ApplicationContextProvider;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.hibernate.validator.constraints.br.CPF;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.*;

@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User {

    @Id
    @GeneratedValue
    @UuidGenerator
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, updatable = false, nullable = false)
    private UUID id;

    private String username;
    private String email;
    private String passwordHash;
    
    @Column(name = "phone_encrypted")
    private String phoneEncrypted;

    @Column(name = "cpf_encrypted", length = 255, unique = true, nullable = false)
    private String cpfEncrypted;

    private LocalDateTime createdAt;
    private LocalDateTime modifiedAt;

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Wallet> wallets = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Alert> alerts = new ArrayList<>();

    // Métodos auxiliares para criptografia
    @Transient
    private EncryptionUtil encryptionUtil;

    public void setPhone(String phone) {
        if (encryptionUtil != null && phone != null) {
            this.phoneEncrypted = encryptionUtil.encrypt(phone);
        }
    }

    public String getPhone() {
        if (encryptionUtil != null && phoneEncrypted != null) {
            return encryptionUtil.decrypt(phoneEncrypted);
        }
        return null;
    }

    public void setCpf(String cpf) {
        if (encryptionUtil != null && cpf != null) {
            this.cpfEncrypted = encryptionUtil.encrypt(cpf);
        }
    }

    public String getCpf() {
        if (encryptionUtil != null && cpfEncrypted != null) {
            return encryptionUtil.decrypt(cpfEncrypted);
        }
        return null;
    }

    @PostLoad
    @PostPersist
    @PostUpdate
    private void initEncryption() {
        try {
            this.encryptionUtil = ApplicationContextProvider.getEncryptionUtil();
        } catch (Exception e) {
            // Log do erro, mas não falha a operação
        }
    }
}