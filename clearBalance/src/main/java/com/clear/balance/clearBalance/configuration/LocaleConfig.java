package com.clear.balance.clearBalance.configuration;

import java.util.Locale;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

@Configuration
public class LocaleConfig {

    /**
     * Configures a LocaleResolver that determines the user's locale
     * based on the HTTP "Accept-Language" header sent by the client (e.g. Angular frontend).
     * 
     * Spring will automatically inject this locale into controller methods
     * or service methods that include a java.util.Locale parameter.
     *
     * Example:
     *   Accept-Language: es -> Locale = "es"
     *   Accept-Language: en-US -> Locale = "en_US"
     *
     * The default locale is set to English if no header is provided.
     */
    @Bean
    public LocaleResolver localeResolver() {
        AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
        localeResolver.setDefaultLocale(Locale.ENGLISH);
        return localeResolver;
    }
}
