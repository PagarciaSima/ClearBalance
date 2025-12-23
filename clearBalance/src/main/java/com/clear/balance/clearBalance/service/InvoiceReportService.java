package com.clear.balance.clearBalance.service;

public interface InvoiceReportService {
	public byte[] generateInvoicePdf(Long invoiceId);
}
