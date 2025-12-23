package com.clear.balance.clearBalance.dto.invoice;

import java.util.Date;
import java.util.List;

import com.clear.balance.clearBalance.dto.customer.CustomerDto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class InvoiceDto {
	private String invoiceNumber;
	private Date date;
	private String status;
	private double total;
	private CustomerDto customer;
	private List<InvoiceServiceDto> services;
}
