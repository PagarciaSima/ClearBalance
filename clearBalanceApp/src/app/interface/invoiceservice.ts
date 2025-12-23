/**
 * Represents a service line in an invoice.
 */
export interface InvoiceService {
  id?: number;
  description: string;
  price: number;
  quantity: number;
}