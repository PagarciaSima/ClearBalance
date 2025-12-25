package com.clear.balance.clearBalance.service;

public interface CustomerReportService {
    byte[] generateAllCustomersExcel();
    byte[] generateAllCustomersCSV();
}
