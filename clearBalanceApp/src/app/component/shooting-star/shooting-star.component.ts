import { Component, OnInit, OnDestroy } from '@angular/core';

interface Star {
  id: number;
  top: string;
  animationDuration: string;
  animationDelay: string;
}

@Component({
  selector: 'app-shooting-star',
  templateUrl: './shooting-star.component.html',
  styleUrls: ['./shooting-star.component.css']
})
export class ShootingStarComponent implements OnInit, OnDestroy {
  stars: Star[] = [];
  private intervalId: any;
  private starIdCounter = 0;

  ngOnInit(): void {
    // Generate the first shooting star immediately
    this.generateStar();
    
    // Generate a shooting star every 3-6 seconds
    this.intervalId = setInterval(() => {
      this.generateStar();
    }, this.getRandomInterval(3000, 6000));
  }

  ngOnDestroy(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  /**
   * Generates a new shooting star at a random position on the screen
   * The star appears in the top 60% of the screen with a random animation duration
   * Stars are automatically removed from the array after their animation completes
   * @private
   */
  private generateStar(): void {
    const screenHeight = window.innerHeight;
    const randomTop = Math.random() * (screenHeight * 0.6); // Only in the top 60%
    const duration = this.getRandomInterval(800, 900); // Faster animation duration
    
    const newStar: Star = {
      id: this.starIdCounter++,
      top: `${randomTop}px`,
      animationDuration: `${duration}ms`,
      animationDelay: '0s'
    };
    
    this.stars.push(newStar);
    
    // Remove the star after its animation completes
    setTimeout(() => {
      this.stars = this.stars.filter(star => star.id !== newStar.id);
    }, duration + 100);
  }

  /**
   * Generates a random interval between min and max milliseconds
   * @param min - Minimum interval in milliseconds
   * @param max - Maximum interval in milliseconds
   * @returns Random interval value
   * @private
   */
  private getRandomInterval(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
}
