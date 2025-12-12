import { Customer } from "./customer";

export interface Invoice {
  id?: number;
  invoiceNumber: string;
  services: string;
  date: string | Date;
  status: string;
  total: number;
  customer?: Customer | null;
}

