package com.clear.balance.clearBalance.configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfiguration {

    @Value("${openapi.server.url}")
    private String serverUrl;

    @Value("${openapi.server.description}")
    private String serverDescription;

    @Bean
    OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("OpenApi specification - Pablo García Simavilla")
                        .version("1.0")
                        .description("OpenApi specification for Clear Balance API")
                        .contact(new Contact()
                                .name("Pablo")
                                .email("pgarcsim2334@hotmail.com")
                                .url("https://www.linkedin.com/in/pablo-garc%C3%ADa-simavilla-756469222/")
                        )
                )
                .addServersItem(new Server()
                        .url(serverUrl)
                        .description(serverDescription)
                )
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .schemaRequirement("bearerAuth", new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .in(io.swagger.v3.oas.models.security.SecurityScheme.In.HEADER)
                );
    }
}
