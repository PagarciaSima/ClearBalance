package com.clear.balance.clearBalance.dto.invoice;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class InvoiceServiceDto {
	private String description;
    private double price;
    private int quantity;
   
}
