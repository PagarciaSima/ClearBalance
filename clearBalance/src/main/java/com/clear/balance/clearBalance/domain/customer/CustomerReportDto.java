package com.clear.balance.clearBalance.domain.customer;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomerReportDto {
	private String name;
	private String email;
	private String type;
	private String status;
	private String address;
	private String phone;
	private Date createdAt;
	private Integer totalInvoices;
	private Double totalAmount;
}