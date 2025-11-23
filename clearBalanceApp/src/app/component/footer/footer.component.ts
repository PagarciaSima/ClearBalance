import { Component } from '@angular/core';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css']
})
export class FooterComponent {
  currentYear: number = new Date().getFullYear();
  stars: { top: string; left: string; delay: string }[] = [];

  constructor() {
    this.generateStars(20);
  }

  generateStars(count: number): void {
    for (let i = 0; i < count; i++) {
      this.stars.push({
        top: Math.random() * 100 + '%',
        left: Math.random() * 100 + '%',
        delay: Math.random() * 3 + 's'
      });
    }
  }
}
