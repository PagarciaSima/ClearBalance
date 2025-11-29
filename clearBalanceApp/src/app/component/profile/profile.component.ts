import { Component, AfterViewInit, OnDestroy, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { TooltipService } from 'src/app/service/tooltip.service';
import { slideBlur } from 'src/app/animations/animations';
import { Router, NavigationStart } from '@angular/router';
import { BehaviorSubject, Observable, of, Subscription } from 'rxjs';
import { map, startWith, catchError } from 'rxjs/operators';
import { DataState } from 'src/app/enum/datastate.enum';
import { UserService } from 'src/app/service/user.service';
import { State } from 'src/app/interface/state';
import { Profile } from 'src/app/interface/profile';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { NotificationService } from 'src/app/service/notification.service';

declare var bootstrap: any;

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css'],
  animations: [
    slideBlur
  ]
})
export class ProfileComponent implements AfterViewInit, OnDestroy, OnInit {

  profileState$!: Observable<State<CustomHttpResponse<Profile>>>;
  private dataSubject = new BehaviorSubject<CustomHttpResponse<Profile> | null>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$: Observable<boolean> = this.isLoadingSubject.asObservable();
  
  readonly DataState = DataState;
  private routerSubscription?: Subscription;

  constructor(
    private tooltipService: TooltipService,
    private router: Router,
    private userService: UserService,
    private notificationService: NotificationService
  ) {
    // Subscribe to router events to clean tooltips before navigation
    this.routerSubscription = this.router.events.subscribe(event => {
      if (event instanceof NavigationStart) {
        this.forceCleanAllTooltips();
      }
    });
  }

  ngOnInit(): void {
    this.loadProfileData();
  }

  /**
   * Loads the user's profile data from the server.
   * Initializes the profileState$ observable with loading, loaded, and error states.
   * Utilizes the UserService to fetch the profile data.
   */
  private loadProfileData(): void {
    this.profileState$ = this.userService.profile$()
      .pipe(
        map(response => {
          console.log('Received response:', response);
          this.dataSubject.next(response);
          return {
            dataState: DataState.LOADED,
            appData: response
          };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: any) => {
          console.log('Error in profile$:', { error });
          const reason = error?.error?.reason || error?.message || 'An unknown error occurred while loading the profile.';
          this.notificationService.showError(reason, 'Profile Load Error');
          return of({ dataState: DataState.ERROR, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value, error });
        })
      );
  }

  /**
   * Updates the user's profile with the provided form data.
   * @param profileForm - The NgForm containing the user's updated profile information
   * @remarks
   * - Sets the loading state to true while the update is in progress
   * - Calls the UserService's update$ method to send the updated profile data to the server
   * - Updates the dataSubject with the new profile data on success
   * - Handles errors by logging them and maintaining the previous profile data
   */
  updateProfile(profileForm: NgForm): void {
    this.isLoadingSubject.next(true);
    this.profileState$ = this.userService.update$(profileForm.value)
      .pipe(
        map(response => {
          console.log('Received response:', response);
          this.dataSubject.next({ ...response, data: response.data });
          this.isLoadingSubject.next(false);
          return {
            dataState: DataState.LOADED,
            appData: this.dataSubject.value === null ? undefined : this.dataSubject.value
          };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value }),
        catchError((error: any) => {
          console.error('Error in updateProfile:', error);
          this.isLoadingSubject.next(false);
          const reason = error?.error?.reason || error?.message || 'An unknown error occurred while updating the profile.';
          this.notificationService.showError(reason, 'Profile Update Error');
          return of({ dataState: DataState.LOADED, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value, error });
        })
      );
  }

  updatePassword(passwordForm: NgForm) {
    this.isLoadingSubject.next(true);
    if (passwordForm.value.newPassword === passwordForm.value.confirmNewPassword) { 
      this.profileState$ = this.userService.updatePassword$(passwordForm.value)
      .pipe(
        map(response => {
          console.log(response);
          passwordForm.reset();
          this.isLoadingSubject.next(false);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value }),
        catchError((error: string) => {
          console.error('Error in updatePassword:', error);
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.LOADED, appData: this.dataSubject.value === null ? undefined : this.dataSubject.value, error });
        })
      );
    } else {
      passwordForm.reset();
      this.isLoadingSubject.next(false);
    }
  }

  /**
   * Returns the user's image URL or a default astronaut image if not available.
   */
  getUserImage(imageUrl?: string): string {
    return imageUrl || 'assets/img/astronaut.png';
  }

  /**
   * Opens the user's address in Google Maps in a new tab.
   */
  viewOnMap(address?: string): void {
    if (address && address.trim()) {
      const encodedAddress = encodeURIComponent(address);
      const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodedAddress}`;
      window.open(mapsUrl, '_blank', 'noopener,noreferrer');
    }
  }

  /**
   * Initializes tooltips after the view has been fully initialized.
   * Only initializes tooltips on non-interactive elements.
   */
  ngAfterViewInit(): void {
    // Small delay to ensure DOM is ready
    setTimeout(() => {
      // Initialize regular tooltips (non-pill buttons)
      this.tooltipService.initialize();
      
      // Add special handling for breadcrumb links to force hide tooltips
      this.addBreadcrumbTooltipHandlers();
    }, 150);
  }

  /**
   * Adds click event handlers to breadcrumb links with tooltips
   * to ensure tooltips are hidden and disposed of when clicked.
   */
  private addBreadcrumbTooltipHandlers(): void {
    const breadcrumbLinks = document.querySelectorAll('.breadcrumb a[data-bs-toggle="tooltip"]');
    breadcrumbLinks.forEach((link) => {
      link.addEventListener('click', () => {
        const tooltip = bootstrap.Tooltip.getInstance(link);
        if (tooltip) {
          tooltip.hide();
          tooltip.dispose();
        }
        // Also remove any tooltip elements
        document.querySelectorAll('.tooltip').forEach(t => t.remove());
      });
    });
  }

  ngOnDestroy(): void {
    this.forceCleanAllTooltips();
    this.tooltipService.hideAll();
    this.routerSubscription?.unsubscribe();
  }

  private forceCleanAllTooltips(): void {
    // Remove all tooltip elements from DOM immediately
    document.querySelectorAll('.tooltip').forEach(tooltip => {
      tooltip.remove();
    });
    
    // Dispose all tooltip instances (only on tooltip elements, not pills)
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(element => {
      const tooltip = bootstrap.Tooltip.getInstance(element);
      if (tooltip) {
        tooltip.hide();
        tooltip.dispose();
      }
    });
  }



updateAccountSettings(_t149: NgForm) {
throw new Error('Method not implemented.');
}
updateRole(_t125: NgForm) {
throw new Error('Method not implemented.');
}


toggleMfa() {
throw new Error('Method not implemented.');
}
  // Password visibility toggles
  showCurrentPassword: boolean = false;
  showNewPassword: boolean = false;
  showConfirmPassword: boolean = false;

  // Avatar upload handler
  onAvatarChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files[0]) {
      const file = input.files[0];
      const reader = new FileReader();
      
      reader.onload = (e: ProgressEvent<FileReader>) => {
        // Here you would update the avatar image
        console.log('Avatar selected:', file.name);
        // TODO: Upload to server and update profile
      };
      
      reader.readAsDataURL(file);
    }
  }
}
