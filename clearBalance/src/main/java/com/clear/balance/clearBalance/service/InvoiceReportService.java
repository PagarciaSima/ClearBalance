package com.clear.balance.clearBalance.service;

public interface InvoiceReportService {
	public byte[] generateInvoicePdf(Long invoiceId);

	byte[] generateAllInvoicesExcel();

	public byte[] generateAllInvoicesCSVSimple();
}
