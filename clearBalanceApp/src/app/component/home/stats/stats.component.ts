import { Component, OnInit } from '@angular/core';
import { Stats } from 'src/app/interface/stats';
import { CustomerService } from 'src/app/service/customer.service';


@Component({
  selector: 'app-stats',
  templateUrl: './stats.component.html',
  styleUrls: ['./stats.component.css']
})
export class StatsComponent implements OnInit {

  stats: Stats | null = null;
  loading = false;
  error: string | null = null;

  /**
   * Initializes the component and fetches global statistics.
   * @param customerService Injected CustomerService for API calls
   */
  constructor(private customerService: CustomerService) {}

  /**
   * Lifecycle hook that is called after data-bound properties are initialized.
   * Initiates the loading of global statistics.
   */
  ngOnInit(): void {
    this.fetchStats();
  }

  /**
   * Fetches global statistics from the server and updates the component state.
   */
  fetchStats(): void {
    this.loading = true;
    this.error = null;
    this.customerService.getGlobalStats$().subscribe({
      next: (response) => {
        const stats: Partial<Stats> = response.data?.stats || {};
        this.stats = {
          totalCustomers: stats.totalCustomers ?? 0,
          totalInvoices: stats.totalInvoices ?? 0,
          totalBilled: stats.totalBilled ?? 0,
        };
        this.loading = false;
      },
      error: (err) => {
        console.error('Error fetching stats:', err);
        this.loading = false;
      }
    });
  }
}
