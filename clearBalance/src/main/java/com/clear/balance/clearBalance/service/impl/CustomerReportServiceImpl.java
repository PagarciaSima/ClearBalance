package com.clear.balance.clearBalance.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.customer.Customer;
import com.clear.balance.clearBalance.domain.customer.CustomerReportDto;
import com.clear.balance.clearBalance.service.CustomerReportService;
import com.clear.balance.clearBalance.service.CustomerService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;
import net.sf.jasperreports.engine.export.ooxml.JRXlsxExporter;
import net.sf.jasperreports.export.SimpleExporterInput;
import net.sf.jasperreports.export.SimpleOutputStreamExporterOutput;
import net.sf.jasperreports.export.SimpleXlsxReportConfiguration;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomerReportServiceImpl implements CustomerReportService {

	private final CustomerService customerService;

	/**
	 * Generates an Excel report containing all customers in the system.
	 * <p>
	 * This method retrieves all customers from the customer service, converts them
	 * into {@link CustomerReportDto} objects, and uses a JasperReports Excel
	 * template to generate an XLSX file.
	 * </p>
	 *
	 * <p>
	 * The report is created using the JasperReports engine by:
	 * </p>
	 * <ul>
	 * <li>Loading and compiling the JRXML Excel template</li>
	 * <li>Filling the report with customer data and report parameters</li>
	 * <li>Exporting the filled report to an Excel (XLSX) format</li>
	 * </ul>
	 *
	 * <p>
	 * If no customers are found or if the report template cannot be loaded, a
	 * {@link RuntimeException} is thrown.
	 * </p>
	 *
	 * @return a byte array representing the generated Excel file
	 * @throws RuntimeException if no customers are found or if an error occurs
	 *                          during the Excel report generation process
	 */
	@Override
	public byte[] generateAllCustomersExcel() {
		log.info("Starting Excel generation for all customers");

		try {
			List<Customer> customers = StreamSupport.stream(customerService.getCustomers().spliterator(), false)
					.toList();
			if (customers == null || customers.isEmpty()) {
				log.warn("No customers found in the system");
				throw new RuntimeException("No customers found in the system");
			}

			log.info("Converting {} customers to report DTOs", customers.size());

			List<CustomerReportDto> customerList = customers.stream().map(this::convertToReportDto)
					.collect(Collectors.toList());

			log.info("Loading and compiling Excel report template");

			InputStream excelReportStream = getClass().getResourceAsStream("/reports/customers_list_excel.jrxml");

			if (excelReportStream == null) {
				log.error("Customer Excel report template not found: /reports/customers_list_excel.jrxml");
				throw new RuntimeException(
						"Customer Excel report template not found: /reports/customers_list_excel.jrxml");
			}

			JasperReport excelReport = JasperCompileManager.compileReport(excelReportStream);

			Map<String, Object> parameters = new HashMap<>();
			parameters.put("REPORT_TITLE", "Customers Report - Clear Balance");
			parameters.put("GENERATED_DATE", new Date());

			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(customerList);

			log.info("Filling report and exporting to Excel");

			JasperPrint jasperPrint = JasperFillManager.fillReport(excelReport, parameters, dataSource);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			JRXlsxExporter exporter = new JRXlsxExporter();
			exporter.setExporterInput(new SimpleExporterInput(jasperPrint));
			exporter.setExporterOutput(new SimpleOutputStreamExporterOutput(outputStream));

			SimpleXlsxReportConfiguration configuration = new SimpleXlsxReportConfiguration();
			configuration.setOnePagePerSheet(false);
			configuration.setRemoveEmptySpaceBetweenRows(true);
			configuration.setRemoveEmptySpaceBetweenColumns(true);
			configuration.setWhitePageBackground(false);
			configuration.setDetectCellType(true);
			configuration.setSheetNames(new String[] { "Customers List" });
			configuration.setCollapseRowSpan(false);

			exporter.setConfiguration(configuration);
			exporter.exportReport();

			byte[] excelBytes = outputStream.toByteArray();

			log.info("Customers Excel successfully generated ({} bytes)", excelBytes.length);
			return excelBytes;

		} catch (Exception e) {
			log.error("Error while generating customers Excel report", e);
			throw new RuntimeException("Error generating customers Excel report: " + e.getMessage(), e);
		}
	}

	/**
	 * Generates a CSV report containing all customers in the system.
	 * <p>
	 * This method retrieves all customers from the customer service and builds a
	 * CSV document in memory with customer details and aggregated invoice data.
	 * </p>
	 *
	 * <p>
	 * The generated CSV includes:
	 * </p>
	 * <ul>
	 * <li>Basic customer information (name, email, type, status, etc.)</li>
	 * <li>Total number of invoices per customer</li>
	 * <li>Total invoiced amount including taxes</li>
	 * </ul>
	 *
	 * <p>
	 * The CSV is generated using UTF-8 encoding and includes a BOM to ensure
	 * compatibility with Microsoft Excel.
	 * </p>
	 *
	 * @return a byte array representing the generated CSV file
	 * @throws RuntimeException if an error occurs while generating the CSV report
	 */
	@Override
	public byte[] generateAllCustomersCSV() {
		try {
			log.info("Fetching all customers from the customer service");

			List<Customer> customers = StreamSupport.stream(customerService.getCustomers().spliterator(), false)
					.toList();

			log.debug("Number of customers fetched: {}", customers.size());

			StringBuilder csv = new StringBuilder();

			// UTF-8 BOM for Excel compatibility
			csv.append("\uFEFF");

			csv.append("Name,Email,Type,Status,Address,Phone,Created At,Total Invoices,Total Amount ($)\r\n");

			SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");

			DecimalFormatSymbols symbols = new DecimalFormatSymbols(Locale.US);
			symbols.setDecimalSeparator('.');
			DecimalFormat numberFormat = new DecimalFormat("0.00", symbols);

			for (Customer customer : customers) {

				double totalAmount = customer.getInvoices().stream()
						.mapToDouble(invoice -> invoice.getTotal() + (invoice.getTotal() * 0.054)).sum();

				csv.append(escapeCsv(customer.getName())).append(",").append(escapeCsv(customer.getEmail())).append(",")
						.append(escapeCsv(customer.getType())).append(",").append(escapeCsv(customer.getStatus()))
						.append(",").append(escapeCsv(customer.getAddress())).append(",")
						.append(escapeCsv(customer.getPhone())).append(",")
						.append(dateFormat.format(customer.getCreatedAt())).append(",")
						.append(customer.getInvoices().size()).append(",").append(numberFormat.format(totalAmount))
						.append("\r\n");
			}

			log.info("Customers CSV generation completed successfully");
			return csv.toString().getBytes(StandardCharsets.UTF_8);

		} catch (Exception e) {
			log.error("Error generating customers CSV", e);
			throw new RuntimeException("Error generating customers CSV: " + e.getMessage(), e);
		}
	}

	/**
	 * Converts a {@link Customer} entity into a {@link CustomerReportDto} suitable
	 * for reporting purposes.
	 * <p>
	 * This method aggregates invoice data to calculate the total number of invoices
	 * and the total invoiced amount including taxes.
	 * </p>
	 *
	 * @param customer the customer entity to convert
	 * @return a populated {@link CustomerReportDto} containing report-ready data
	 */
	private CustomerReportDto convertToReportDto(Customer customer) {

		double totalAmount = customer.getInvoices().stream()
				.mapToDouble(invoice -> invoice.getTotal() + (invoice.getTotal() * 0.054)).sum();

		return CustomerReportDto.builder().name(customer.getName()).email(customer.getEmail()).type(customer.getType())
				.status(customer.getStatus()).address(customer.getAddress()).phone(customer.getPhone())
				.createdAt(customer.getCreatedAt()).totalInvoices(customer.getInvoices().size())
				.totalAmount(totalAmount).build();
	}

	/**
	 * Escapes a value to make it safe for inclusion in a CSV file.
	 * <p>
	 * If the value contains commas, quotes, or line breaks, it is wrapped in double
	 * quotes and any existing quotes are escaped according to CSV format rules.
	 * </p>
	 *
	 * @param value the raw value to escape
	 * @return a CSV-safe string representation of the value, or an empty string if
	 *         the input value is null or empty
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

}
