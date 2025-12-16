import { Invoice } from "./invoice";
import { Page } from "./page";

export interface Customer {
  id?: number;
  name: string;
  email: string;
  type: string;
  status: string;
  address: string;
  phone: string;
  imageUrl: string;
  createdAt: string | Date;
  invoices?: Invoice[];
}

export interface CustomerPage {
  customers: Page<Customer>;
}
