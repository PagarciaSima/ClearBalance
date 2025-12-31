import { Component, OnInit, OnDestroy, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-ufo',
  templateUrl: './ufo.component.html',
  styleUrls: ['./ufo.component.css'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class UfoComponent implements OnInit, OnDestroy {
  ufoStyle: any = {};
  isAbducting = false;
  showBeam = false;
  private intervalId: any;
  private abductionCheckInterval: any;

  ngOnInit(): void {
    this.moveUfo();
    // Move the UFO every 5-8 seconds randomly
    this.intervalId = setInterval(() => {
      // Don't move if currently abducting
      if (!this.isAbducting) {
        this.moveUfo();
      }
    }, this.getRandomInterval(5000, 8000));

    // Check for abduction opportunity every 20-30 seconds
    this.abductionCheckInterval = setInterval(() => {
      // Only attempt if not currently abducting
      if (!this.isAbducting) {
        this.attemptAbduction();
      }
    }, this.getRandomInterval(20000, 30000));
  }

  ngOnDestroy(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
    if (this.abductionCheckInterval) {
      clearInterval(this.abductionCheckInterval);
    }
  }

  /**
   * Moves the UFO to a random position on the screen
   * Only moves if the UFO is not currently performing an abduction
   * @private
   */
  private moveUfo(): void {
    // Don't move if currently abducting
    if (this.isAbducting) {
      return;
    }

    const maxX = window.innerWidth - 100; // 100px is the approximate width of the UFO
    const maxY = window.innerHeight - 100;
    
    const randomX = Math.random() * maxX;
    const randomY = Math.random() * maxY;
    
    this.ufoStyle = {
      left: `${randomX}px`,
      top: `${randomY}px`
    };
  }

  /**
   * Attempts to abduct the person icon if it exists on the page
   * Positions the UFO above the person, shows the beam, and animates the abduction sequence
   * @private
   */
  private attemptAbduction(): void {
    const personIcon = document.querySelector('.person-icon') as HTMLElement;
    if (!personIcon || this.isAbducting) return;

    const personRect = personIcon.getBoundingClientRect();
    const personX = personRect.left + personRect.width / 2;
    const personY = personRect.top;

    // Get the UFO element to calculate its actual width
    const ufoElement = document.querySelector('.ufo-container img') as HTMLElement;
    const ufoWidth = ufoElement ? ufoElement.offsetWidth : 100;

    // Mark as abducting to prevent movement
    this.isAbducting = true;

    // Position UFO above the person, centered properly
    this.ufoStyle = {
      left: `${personX - (ufoWidth / 2)}px`,  // centered above person
      top: `${personY - 150}px`,
      transition: 'all 2s ease-in-out'
    };

    // Start abduction sequence
    setTimeout(() => {
      this.showBeam = true;
      personIcon.classList.add('being-abducted');

      // End abduction after 3.5 seconds (duration of animation)
      setTimeout(() => {
        this.showBeam = false;
        
        // Wait 3 seconds before person reappears
        setTimeout(() => {
          personIcon.classList.remove('being-abducted');
          personIcon.classList.add('reappearing');
          
          // Remove reappearing class after animation completes
          setTimeout(() => {
            personIcon.classList.remove('reappearing');
          }, 1000);
        }, 3000);
        
        // Wait a bit before allowing UFO to move again
        setTimeout(() => {
          this.isAbducting = false;
          // Move UFO away
          this.moveUfo();
        }, 500);
      }, 3500);
    }, 2000);
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