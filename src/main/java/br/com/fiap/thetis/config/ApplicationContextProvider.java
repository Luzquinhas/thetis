package br.com.fiap.thetis.config;

import br.com.fiap.thetis.util.EncryptionUtil;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class ApplicationContextProvider implements ApplicationContextAware {
    
    private static ApplicationContext context;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        context = applicationContext;
    }

    public static ApplicationContext getApplicationContext() {
        return context;
    }

    public static EncryptionUtil getEncryptionUtil() {
        return context.getBean(EncryptionUtil.class);
    }
}

