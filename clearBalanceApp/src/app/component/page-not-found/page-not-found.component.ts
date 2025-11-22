import { Component } from '@angular/core';
import { Location } from '@angular/common';
import { bounceIn } from 'src/app/animations/animations';

@Component({
  selector: 'app-page-not-found',
  templateUrl: './page-not-found.component.html',
  styleUrls: ['./page-not-found.component.css'],
  animations: [
    bounceIn
  ]
})
export class PageNotFoundComponent {
  /** Number of UFOs to display on the 404 page */
  ufos = [1, 2, 3];

  constructor(private location: Location) {}

  /**
   * Navigates back to the previous page in browser history
   */
  goBack(): void {
    this.location.back();
  }
}
