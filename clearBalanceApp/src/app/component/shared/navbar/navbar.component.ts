import { Component, AfterViewInit, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { Router } from '@angular/router';
import { TooltipService } from 'src/app/service/tooltip.service';
import { Key } from 'src/app/enum/key.enum';
import { UserService } from 'src/app/service/user.service';
import { Profile } from 'src/app/interface/profile';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class NavbarComponent implements AfterViewInit, OnInit {

  stars: { top: string; left: string; delay: string }[] = [];
  userFullName: string = '';
  profile: Profile | null = null;

  constructor(
    private tooltipService: TooltipService,
    private router: Router,
    private userService: UserService
  ) {
    this.generateStars(8);
  }

  /**
   * Initializes the component by checking authentication status and fetching user profile if authenticated.
   * This method is called once the component is created.
   */
  ngOnInit(): void {
    if (this.isAuthenticated()) {
      this.getCurrentUser();
      this.listenProfileUpdates();
    }
  }

  /**
   * Checks if the user is authenticated by verifying the presence of the token in localStorage.
   * @returns True if the user is authenticated, false otherwise.
   */
  private isAuthenticated(): boolean {
    return !!localStorage.getItem(Key.TOKEN);
  }
  /**
   * Listens for profile updates from the UserService.
   * Updates the userFullName and profile properties when a new profile is received.
   * This method ensures that the component reflects the latest user profile information.
   */
  private listenProfileUpdates() {
    this.userService.profile$Shared.subscribe(profile => {
      if (profile && profile.user) {
        this.profile = profile;
        this.userFullName = `${profile.user.firstName} ${profile.user.lastName}`;
      }
    });
  }

  /**
   * Fetches the current user's profile information
   */
  private getCurrentUser() {
    this.userService.profile$().subscribe(resp => {
      this.profile = resp.data ?? null;
      console.log('Navbar profile:', this.profile);
      if (this.profile && this.profile.user) {
        this.userFullName = `${this.profile.user.firstName} ${this.profile.user.lastName}`;
      }
    });
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
