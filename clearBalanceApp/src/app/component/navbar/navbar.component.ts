import { Component, AfterViewInit } from '@angular/core';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements AfterViewInit {
  stars: { top: string; left: string; delay: string }[] = [];

  constructor(private tooltipService: TooltipService) {
    this.generateStars(8);
  }

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  private generateStars(count: number): void {
    for (let i = 0; i < count; i++) {
      this.stars.push({
        top: Math.random() * 100 + '%',
        left: Math.random() * 100 + '%',
        delay: Math.random() * 3 + 's'
      });
    }
  }

  logOut() {
    throw new Error('Method not implemented.');
  }

}
