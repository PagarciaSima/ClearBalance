import { AfterViewInit, Component, OnDestroy, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { NavigationStart, Router } from '@angular/router';
import { BehaviorSubject, Observable, of, Subscription } from 'rxjs';
import { catchError, map, startWith } from 'rxjs/operators';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { PagedEvents } from 'src/app/interface/events';
import { Profile } from 'src/app/interface/profile';
import { State } from 'src/app/interface/state';
import { NotificationService } from 'src/app/service/notification.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { UserService } from 'src/app/service/user.service';

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
  private routerSubscription?: Subscription;
  isLoading$: Observable<boolean> = this.isLoadingSubject.asObservable();
  showCurrentPassword: boolean = false;
  showNewPassword: boolean = false;
  showConfirmPassword: boolean = false;
  readonly DataState = DataState;
  imageTimestamp: number = Date.now();
  
  eventsPage?: PagedEvents;
  currentPage: number = 0;
  eventsPageSize: number = 10;

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
    this.loadEvents();
  }

  /**
   * Handles page change events from the pagination component.
   * @param page - The new page number to load
   */
  onPageChange(page: number): void {
    this.loadEvents(page);
  }

  /**
   * Loads the user's events for the specified page.
   * @param eventsPageSize - The page number to load (default is 0)
   */
  loadEvents(page: number = 0): void {
    this.userService.getUserEvents$(page, this.eventsPageSize).subscribe(response => {
      this.eventsPage = response?.data?.events;
      this.currentPage = this.eventsPage?.number || 0;
    });
  }

  /**
   * Cleans up tooltips and unsubscribes from router events when the component is destroyed.
   */
  ngOnDestroy(): void {
    this.forceCleanAllTooltips();
    this.tooltipService.hideAll();
    this.routerSubscription?.unsubscribe();
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
   * Forces the removal and disposal of all tooltips in the DOM.
   * This is useful to prevent lingering tooltips during navigation.
   */
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
          this.loadEvents(this.currentPage);
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

  /**
   * Updates the user's password with the provided form data.
   * @param passwordForm - The NgForm containing the user's current and new password information
   * @remarks
   * - Sets the loading state to true while the update is in progress
   * - Validates that the new password and confirm new password fields match
   * - Calls the UserService's updatePassword$ method to send the new password data to the server
   * - Resets the form and updates the dataSubject on success
   * - Handles errors by logging them and maintaining the previous profile data
   */
  updatePassword(passwordForm: NgForm): void {
    this.isLoadingSubject.next(true);
    if (passwordForm.value.newPassword === passwordForm.value.confirmNewPassword) { 
      this.profileState$ = this.userService.updatePassword$(passwordForm.value)
      .pipe(
        map(response => {
          console.log(response);
          passwordForm.reset();
          this.isLoadingSubject.next(false);
          this.loadEvents(this.currentPage);
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
   * Updates the user's role with the provided form data.
   * @param roleForm - The NgForm containing the new role name
   * @remarks
   * - Sets the loading state to true while the update is in progress
   * - Calls the UserService's updateRole$ method to send the new role data to the server
   * - Updates the dataSubject with the new profile data on success
   * - Handles errors by logging them and maintaining the previous profile data
   */
  updateRole(roleForm: NgForm): void {
    this.isLoadingSubject.next(true);
    this.profileState$ = this.userService.updateRole$(roleForm.value.roleName)
      .pipe(
        map(response => {
          console.log(response);
          this.dataSubject.next({ ...response, data: response.data });
          this.isLoadingSubject.next(false);
          this.loadEvents(this.currentPage);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.LOADED, appData: this.dataSubject.value, error })
        })
      )
  }

  /**
   * Updates the user's account settings with the provided form data.
   * @param settingsForm - The NgForm containing the account settings to be updated
   * @remarks
   * - Sets the loading state to true while the update is in progress
   * - Calls the UserService's updateSettings$ method to send the updated settings to the server
   * - Updates the dataSubject with the new profile data on success
   * - Handles errors by logging them and maintaining the previous profile data
   */
  updateAccountSettings(settingsForm: NgForm) {
    this.isLoadingSubject.next(true);
    this.profileState$ = this.userService.updateSettings$(settingsForm.value)
      .pipe(
        map(response => {
          console.log('Settings updated:', response);
          this.dataSubject.next({ ...response, data: response.data });
          this.isLoadingSubject.next(false);
          this.loadEvents(this.currentPage);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };

        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.LOADED, appData: this.dataSubject.value, error })
        })
      );
  }

  /**
   * Toggles the user's multi-factor authentication (MFA) setting.
   * @remarks
   * - Sets the loading state to true while the toggle is in progress
   * - Calls the UserService's toggleMfa$ method to update the MFA setting on the server
   * - Updates the dataSubject with the new profile data on success
   * - Handles errors by logging them and maintaining the previous profile data
   */
  toggleMfa() {
    this.isLoadingSubject.next(true);
    this.profileState$ = this.userService.toggleMfa$()
      .pipe(
        map(response => {
          console.log('toggleMfa:', response);
          this.dataSubject.next({ ...response, data: response.data });
          this.isLoadingSubject.next(false);
          this.loadEvents(this.currentPage);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };

        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.LOADED, appData: this.dataSubject.value, error })
        })
      );
  }

  /**
   * Updates the user's profile image.
   * @param image - The new profile image file to be uploaded
   * @remarks
   * - Sets the loading state to true while the update is in progress
   * - Calls the UserService's updateImage$ method to upload the new image to the server
   * - Updates the dataSubject with the new profile data on success
   * - Updates the imageTimestamp to force reload of the image
   * - Handles errors by logging them and maintaining the previous profile data
   */
  updateProfileImage(image: File) {
    if(image) {
      this.isLoadingSubject.next(true);
      this.profileState$ = this.userService.updateImage$(this.getFormData(image))
        .pipe(
          map(response => {
            console.log('updateProfileImage:', response);
            this.dataSubject.next({ ...response, data: response.data });
            this.isLoadingSubject.next(false);
            this.imageTimestamp = Date.now(); 
            this.loadEvents(this.currentPage);
            return { dataState: DataState.LOADED, appData: this.dataSubject.value };

          }),
          startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
          catchError((error: string) => {
            this.isLoadingSubject.next(false);
            return of({ dataState: DataState.LOADED, appData: this.dataSubject.value, error })
          })
      );
    }
  }

  /**
   * Converts a File object into FormData for HTTP requests.
   * @param image - The image file to be converted
   */
  private getFormData(image: File): FormData {
    const formData = new FormData();
    formData.append('image', image);
    return formData;
  }

  /**
   * Returns the user's image URL or a default astronaut image if not available.
   */
  getUserImage(imageUrl?: string): string {
    if (!imageUrl) {
      return 'assets/img/astronaut.png';
    }
    return `${imageUrl}?t=${this.imageTimestamp}`;
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

  // Avatar upload handler
  onAvatarChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files[0]) {
      const file = input.files[0];
      this.updateProfileImage(file);
    }
  }

}