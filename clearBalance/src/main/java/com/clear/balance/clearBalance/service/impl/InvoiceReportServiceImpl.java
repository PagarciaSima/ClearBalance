package com.clear.balance.clearBalance.service.impl;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.invoice.Invoice;
import com.clear.balance.clearBalance.dto.customer.CustomerDto;
import com.clear.balance.clearBalance.dto.invoice.InvoiceDto;
import com.clear.balance.clearBalance.dto.invoice.InvoiceServiceDto;
import com.clear.balance.clearBalance.service.CustomerService;
import com.clear.balance.clearBalance.service.InvoiceReportService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperExportManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;

@Slf4j
@RequiredArgsConstructor
@Service
public class InvoiceReportServiceImpl implements InvoiceReportService {

	private final CustomerService customerService;

	/**
	 * Generates a PDF document for the given invoice ID.
	 * <p>
	 * This method retrieves the invoice data, converts it to a DTO, compiles the
	 * JasperReports templates (main report and subreport), fills the report with
	 * data, and exports the result to a PDF byte array.
	 * </p>
	 *
	 * @param invoiceId the unique identifier of the invoice
	 * @return a byte array containing the generated PDF
	 * @throws RuntimeException if the invoice is not found or if any error occurs
	 *                          during PDF generation
	 */
	public byte[] generateInvoicePdf(Long invoiceId) {

		log.info("Starting PDF generation for invoice ID: {}", invoiceId);

		try {
			Invoice invoice = customerService.getInvoice(invoiceId);
			if (invoice == null) {
				log.warn("Invoice not found for ID: {}", invoiceId);
				throw new RuntimeException("Invoice not found with id: " + invoiceId);
			}

			InvoiceDto invoiceDto = convertToDto(invoice);

			log.info("Loading and compiling JasperReports templates");

			InputStream mainReportStream = getClass().getResourceAsStream("/reports/invoice_simple.jrxml");
			if (mainReportStream == null) {
				log.error("Main report template not found: /reports/invoice_simple.jrxml");
				throw new RuntimeException("Main report template not found: /reports/invoice_simple.jrxml");
			}

			InputStream subReportStream = getClass().getResourceAsStream("/reports/services_subreport.jrxml");
			if (subReportStream == null) {
				log.error("Subreport template not found: /reports/services_subreport.jrxml");
				throw new RuntimeException("Subreport template not found: /reports/services_subreport.jrxml");
			}

			JasperReport mainReport = JasperCompileManager.compileReport(mainReportStream);
			JasperReport subReport = JasperCompileManager.compileReport(subReportStream);

			Map<String, Object> parameters = new HashMap<>();
			parameters.put("servicesSubreport", subReport);

			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(Arrays.asList(invoiceDto));

			log.info("Filling report and exporting to PDF");

			JasperPrint jasperPrint = JasperFillManager.fillReport(mainReport, parameters, dataSource);

			byte[] pdfBytes = JasperExportManager.exportReportToPdf(jasperPrint);

			log.info("PDF successfully generated ({} bytes)", pdfBytes.length);
			return pdfBytes;

		} catch (Exception e) {
			log.error("Error while generating invoice PDF for ID: {}", invoiceId, e);
			throw new RuntimeException("Error generating invoice PDF: " + e.getMessage(), e);
		}
	}

	/**
	 * Converts an {@link Invoice} entity into an {@link InvoiceDto}.
	 * <p>
	 * This method maps the invoice domain object to a DTO structure suitable for
	 * report generation and data transfer, including customer information and
	 * invoice services.
	 * </p>
	 *
	 * @param invoice the invoice entity to convert
	 * @return a fully populated {@link InvoiceDto}
	 */
	private InvoiceDto convertToDto(Invoice invoice) {

		log.debug("Converting Invoice entity to InvoiceDto (invoiceNumber={})", invoice.getInvoiceNumber());

		CustomerDto customerDto = CustomerDto.builder().name(invoice.getCustomer().getName())
				.email(invoice.getCustomer().getEmail()).address(invoice.getCustomer().getAddress())
				.phone(invoice.getCustomer().getPhone()).build();

		java.util.List<InvoiceServiceDto> servicesDto = invoice.getServices().stream().map(this::convertServiceToDto)
				.collect(java.util.stream.Collectors.toList());

		return new InvoiceDto(invoice.getInvoiceNumber(), invoice.getDate(), invoice.getStatus(), invoice.getTotal(),
				customerDto, servicesDto);
	}

	/**
	 * Converts an {@link InvoiceService} entity into an {@link InvoiceServiceDto}.
	 * <p>
	 * The DTO contains only the information required for invoice rendering,
	 * including a truncated description, unit price, and quantity.
	 * </p>
	 *
	 * @param service the invoice service entity to convert
	 * @return an {@link InvoiceServiceDto} instance
	 */
	private InvoiceServiceDto convertServiceToDto(
			com.clear.balance.clearBalance.domain.invoice.InvoiceService service) {

		log.debug("Converting InvoiceService to DTO (description={})", service.getTruncatedDescription());

		return new InvoiceServiceDto(service.getTruncatedDescription(), service.getPrice(), service.getQuantity());
	}

}