import { Injectable, OnDestroy } from '@angular/core';
import { Router, NavigationStart } from '@angular/router';
import { Subscription } from 'rxjs';

declare var bootstrap: any;

/**
 * Service to manage Bootstrap tooltips globally across the application.
 * Handles initialization, cleanup, and automatic hiding on navigation.
 */
@Injectable({
  providedIn: 'root'
})
export class TooltipService implements OnDestroy {
  private routerSubscription?: Subscription;

  constructor(private router: Router) {
    // Hide all tooltips when navigation starts to prevent orphaned tooltips
    this.routerSubscription = this.router.events.subscribe(event => {
      if (event instanceof NavigationStart) {
        this.hideAll();
      }
    });
  }

  ngOnDestroy(): void {
    this.hideAll();
    this.routerSubscription?.unsubscribe();
  }

  /**
   * Initializes all Bootstrap tooltips in the current view.
   * Should be called in AfterViewInit or after dynamic content is loaded.
   */
  initialize(): void {
    // Small delay to ensure DOM is ready
    setTimeout(() => {
      const tooltipTriggerList = Array.from(
        document.querySelectorAll('[data-bs-toggle="tooltip"]')
      );
      tooltipTriggerList.forEach((tooltipTriggerEl) => {
        new bootstrap.Tooltip(tooltipTriggerEl);
      });
    }, 0);
  }

  /**
   * Hides and removes all active Bootstrap tooltips from the DOM.
   * Useful for cleanup and preventing orphaned tooltips during navigation.
   */
  hideAll(): void {
    const tooltips = document.querySelectorAll('.tooltip');
    tooltips.forEach(tooltip => tooltip.remove());
  }

  /**
   * Disposes of a specific tooltip by its trigger element.
   * @param element - The DOM element that triggers the tooltip
   */
  dispose(element: HTMLElement): void {
    const tooltip = bootstrap.Tooltip.getInstance(element);
    if (tooltip) {
      tooltip.dispose();
    }
  }
}
