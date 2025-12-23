import { Customer } from "./customer";
import { InvoiceService } from "./invoiceservice";

/**
 * Represents an invoice entity with a list of services.
 */
export interface Invoice {
  id?: number;
  invoiceNumber: string;
  services: InvoiceService[];
  date: string | Date;
  status: string;
  total: number;
  customer?: Customer | null;
}

