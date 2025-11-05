package com.clear.balance.clearBalance;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class ClearBalanceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClearBalanceApplication.class, args);
	}

}
