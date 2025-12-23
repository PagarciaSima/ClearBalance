package com.clear.balance.clearBalance.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.invoice.Invoice;
import com.clear.balance.clearBalance.domain.invoice.InvoiceService;
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
import net.sf.jasperreports.engine.export.ooxml.JRXlsxExporter;
import net.sf.jasperreports.export.SimpleExporterInput;
import net.sf.jasperreports.export.SimpleOutputStreamExporterOutput;
import net.sf.jasperreports.export.SimpleXlsxReportConfiguration;

@Slf4j
@RequiredArgsConstructor
@Service
public class InvoiceReportServiceImpl implements InvoiceReportService {

	private final CustomerService customerService;

	/**
	 * Generates a PDF document for the given invoice.
	 *
	 * <p>
	 * This method performs the following steps:
	 * <ol>
	 * <li>Retrieves the invoice by its ID</li>
	 * <li>Converts the invoice entity to a DTO</li>
	 * <li>Loads and compiles the main report and its subreport</li>
	 * <li>Fills the report with data and parameters</li>
	 * <li>Exports the result to a PDF byte array</li>
	 * </ol>
	 *
	 * @param invoiceId the unique identifier of the invoice
	 * @return a byte array containing the generated PDF
	 * @throws RuntimeException if the invoice is not found or if PDF generation
	 *                          fails
	 */
	public byte[] generateInvoicePdf(Long invoiceId) {
		log.info("=== STARTING PDF GENERATION FOR INVOICE ID: {} ===", invoiceId);

		try {
			// 1. Retrieve invoice
			Invoice invoice = customerService.getInvoice(invoiceId);
			if (invoice == null) {
				throw new RuntimeException("Invoice not found with id: " + invoiceId);
			}

			// 2. Convert entity to DTO
			InvoiceDto invoiceDto = convertToDto(invoice);

			// 3. Load and compile report templates
			log.info("Loading and compiling Jasper report templates...");

			// Load main report template
			InputStream mainReportStream = getClass().getResourceAsStream("/reports/invoice_simple.jrxml");
			if (mainReportStream == null) {
				throw new RuntimeException("Main report template not found: /reports/invoice_simple.jrxml");
			}

			// Load subreport template
			InputStream subReportStream = getClass().getResourceAsStream("/reports/services_subreport.jrxml");
			if (subReportStream == null) {
				throw new RuntimeException("Subreport template not found: /reports/services_subreport.jrxml");
			}

			// Compile both reports
			JasperReport mainReport = JasperCompileManager.compileReport(mainReportStream);
			JasperReport subReport = JasperCompileManager.compileReport(subReportStream);

			// 4. Prepare parameters (IMPORTANT: pass the compiled subreport)
			Map<String, Object> parameters = new HashMap<>();
			parameters.put("servicesSubreport", subReport);

			// 5. Create data source
			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(java.util.Arrays.asList(invoiceDto));

			// 6. Generate PDF
			log.info("Generating PDF document...");
			JasperPrint jasperPrint = JasperFillManager.fillReport(mainReport, parameters, dataSource);

			byte[] pdfBytes = JasperExportManager.exportReportToPdf(jasperPrint);

			log.info("✓ PDF successfully generated ({} bytes)", pdfBytes.length);
			return pdfBytes;

		} catch (Exception e) {
			log.error("❌ Error while generating invoice PDF", e);
			throw new RuntimeException("Error generating invoice PDF: " + e.getMessage(), e);
		}
	}

	/**
	 * Generates an Excel report with all invoices.
	 *
	 * @return a byte array containing the generated Excel file
	 * @throws RuntimeException if any error occurs during Excel generation
	 */
	@Override
	public byte[] generateAllInvoicesExcel() {
		log.info("Starting Excel generation for all invoices");

		try {
			// Obtener todas las facturas
			List<Invoice> invoices = customerService.getAllInvoices();
			if (invoices == null || invoices.isEmpty()) {
				log.warn("No invoices found in the system");
				throw new RuntimeException("No invoices found in the system");
			}

			log.info("Converting {} invoices to DTO", invoices.size());

			List<InvoiceDto> invoiceList = invoices.stream().map(this::convertToDto).collect(Collectors.toList());

			log.info("Loading and compiling Excel report template");

			InputStream excelReportStream = getClass().getResourceAsStream("/reports/invoice_list_excel.jrxml");
			if (excelReportStream == null) {
				log.error("Excel report template not found: /reports/invoice_list_excel.jrxml");
				throw new RuntimeException("Excel report template not found: /reports/invoice_list_excel.jrxml");
			}

			JasperReport excelReport = JasperCompileManager.compileReport(excelReportStream);

			Map<String, Object> parameters = new HashMap<>();
			parameters.put("REPORT_TITLE", "All Invoices - Clear Balance");

			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(invoiceList);

			log.info("Filling report and exporting to Excel");

			JasperPrint jasperPrint = JasperFillManager.fillReport(excelReport, parameters, dataSource);

			// Exportar a Excel
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			// Usar JRXlsxExporter para mejor compatibilidad con Excel
			JRXlsxExporter exporter = new JRXlsxExporter();
			exporter.setExporterInput(new SimpleExporterInput(jasperPrint));
			exporter.setExporterOutput(new SimpleOutputStreamExporterOutput(outputStream));

			// Configurar propiedades para Excel
			SimpleXlsxReportConfiguration configuration = new SimpleXlsxReportConfiguration();
			configuration.setOnePagePerSheet(false);
			configuration.setRemoveEmptySpaceBetweenRows(true);
			configuration.setRemoveEmptySpaceBetweenColumns(true);
			configuration.setWhitePageBackground(false);
			configuration.setDetectCellType(true);
			configuration.setSheetNames(new String[] { "All Invoices" });

			exporter.setConfiguration(configuration);
			exporter.exportReport();

			byte[] excelBytes = outputStream.toByteArray();

			log.info("Excel successfully generated ({} bytes)", excelBytes.length);
			return excelBytes;

		} catch (Exception e) {
			log.error("Error while generating all invoices Excel", e);
			throw new RuntimeException("Error generating all invoices Excel: " + e.getMessage(), e);
		}
	}
	
	/**
	 * Generates a simple CSV containing all invoices.
	 * <p>
	 * Each row includes invoice number, date, customer info, status, number of services,
	 * and total including a 5.4% tax. The CSV is UTF-8 encoded with BOM for Excel compatibility.
	 * </p>
	 *
	 * @return a byte array representing the CSV file
	 */
	public byte[] generateAllInvoicesCSVSimple() {
	    try {
	        log.info("Fetching all invoices from the customer service");
	        List<Invoice> invoices = customerService.getAllInvoices();
	        log.debug("Number of invoices fetched: {}", invoices.size());

	        StringBuilder csv = new StringBuilder();
	        csv.append("\uFEFF"); // UTF-8 BOM for Excel compatibility
	        csv.append("Invoice #,Date,Customer,Email,Status,Services,Total ($)\r\n");

	        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");

	        DecimalFormatSymbols symbols = new DecimalFormatSymbols(Locale.US);
	        symbols.setDecimalSeparator('.');
	        DecimalFormat numberFormat = new DecimalFormat("0.00", symbols);

	        for (Invoice invoice : invoices) {
	            String customerName = escapeCsv(invoice.getCustomer().getName());
	            String customerEmail = escapeCsv(invoice.getCustomer().getEmail());
	            String status = escapeCsv(invoice.getStatus());

	            double totalWithTax = invoice.getTotal() + (invoice.getTotal() * 0.054);

	            csv.append(escapeCsv(invoice.getInvoiceNumber())).append(",")
	               .append(dateFormat.format(invoice.getDate())).append(",")
	               .append(customerName).append(",")
	               .append(customerEmail).append(",")
	               .append(status).append(",")
	               .append(invoice.getServices().size()).append(",")
	               .append(numberFormat.format(totalWithTax))
	               .append("\r\n"); // add newline per invoice
	        }

	        log.info("CSV generation completed successfully");
	        return csv.toString().getBytes(StandardCharsets.UTF_8);

	    } catch (Exception e) {
	        log.error("Error generating invoice CSV", e);
	        throw new RuntimeException("Error generating CSV: " + e.getMessage(), e);
	    }
	}

	/**
	 * Escapes a CSV field value if necessary by enclosing it in quotes and
	 * doubling any internal quotes.
	 *
	 * @param value the field value to escape
	 * @return the escaped CSV field
	 */
	private String escapeCsv(String value) {
	    if (value == null || value.isEmpty()) {
	        return "";
	    }

	    if (value.contains(",") || value.contains("\"") || value.contains("\r") || value.contains("\n")) {
	        return "\"" + value.replace("\"", "\"\"") + "\"";
	    }

	    return value;
	}

	/**
	 * Converts an {@link Invoice} entity into an {@link InvoiceDto}.
	 *
	 * <p>The conversion includes:
	 * <ul>
	 *   <li>Mapping customer information to {@link CustomerDto}</li>
	 *   <li>Mapping all invoice services to {@link InvoiceServiceDto}</li>
	 * </ul>
	 *
	 * @param invoice the invoice entity to convert
	 * @return a fully populated {@link InvoiceDto}
	 */
	private InvoiceDto convertToDto(Invoice invoice) {

	    CustomerDto customerDto = CustomerDto.builder()
	            .name(invoice.getCustomer().getName())
	            .email(invoice.getCustomer().getEmail())
	            .address(invoice.getCustomer().getAddress())
	            .phone(invoice.getCustomer().getPhone())
	            .build();

	    List<InvoiceServiceDto> servicesDto = invoice.getServices()
	            .stream()
	            .map(this::convertServiceToDto)
	            .collect(Collectors.toList());

	    return new InvoiceDto(
	            invoice.getInvoiceNumber(),
	            invoice.getDate(),
	            invoice.getStatus(),
	            invoice.getTotal(),
	            customerDto,
	            servicesDto
	    );
	}

	/**
	 * Converts an {@link com.clear.balance.clearBalance.domain.invoice.InvoiceService}
	 * entity into an {@link InvoiceServiceDto}.
	 *
	 * @param service the invoice service entity to convert
	 * @return a corresponding {@link InvoiceServiceDto}
	 */
	private InvoiceServiceDto convertServiceToDto(
	        InvoiceService service) {

	    return new InvoiceServiceDto(
	            service.getDescription(),
	            service.getPrice(),
	            service.getQuantity()
	    );
	}

}