import { Component, AfterViewInit } from '@angular/core';
import { Router } from '@angular/router';
import { TooltipService } from 'src/app/service/tooltip.service';
import { Key } from 'src/app/enum/key.enum';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements AfterViewInit {
  stars: { top: string; left: string; delay: string }[] = [];
  constructor(
    private tooltipService: TooltipService,
    private router: Router
  ) {
    this.generateStars(8);
  }

  /**
   * Initializes tooltips after the view has been initialized.
   */
  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  /**
   * Generates star elements with random positions and animation delays.
   * @param count - The number of stars to generate
   */
  private generateStars(count: number): void {
    for (let i = 0; i < count; i++) {
      this.stars.push({
        top: Math.random() * 100 + '%',
        left: Math.random() * 100 + '%',
        delay: Math.random() * 3 + 's'
      });
    }
  }

  /**
   * Logs out the user by removing authentication tokens from local storage
   * and navigates to the login page.
   */
  logOut(): void {
    localStorage.removeItem(Key.TOKEN);
    localStorage.removeItem(Key.REFRESH_TOKEN);
    this.router.navigate(['/login']);
  }

}
