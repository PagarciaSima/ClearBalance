package com.clear.balance.clearBalance.dto.stats;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class StatsDto {
    private int totalCustomers;
    private int totalInvoices;
    private double totalBilled;
}
