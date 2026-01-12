import { AfterViewInit, Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { RegisterState } from 'src/app/interface/registerState';
import { TooltipService } from 'src/app/service/tooltip.service';
import { UserService } from 'src/app/service/user.service';
import { NotificationService } from 'src/app/service/notification.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css'],
  animations: [ slideBlur]
})
export class RegisterComponent implements AfterViewInit {
  registerState$: Observable<RegisterState> = of({ dataState: DataState.LOADED });
  readonly DataState = DataState;
  showPassword = false;
  showConfirmPassword = false;
  passwordMismatch = false;

  constructor(
    private userService: UserService,
    private tooltipService: TooltipService,
    private notificationService: NotificationService
  ) { }

  /**
   * Angular lifecycle hook that runs after the component's view has been fully initialized.
   * Initializes Bootstrap tooltips for the initial view.
   */
  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  /**
   * Registers a new user using the provided registration form.
   * @param registerForm - The form containing user registration details.
   */
  register(registerForm: NgForm): void {
    const password = registerForm.value.password;
    const confirmPassword = registerForm.value.confirmPassword;
    this.passwordMismatch = password !== confirmPassword;
    if (this.passwordMismatch) {
      return;
    }
    this.registerState$ = this.userService.registerUser$(registerForm.value)
      .pipe(
        map(response => {
          registerForm.reset();
          this.passwordMismatch = false;
          this.notificationService.onSuccess('Registration successful! You can now log in.');
          return { dataState: DataState.LOADED, registerSuccess: true, message: response.message };
        }),
        startWith({ dataState: DataState.LOADING, registerSuccess: false }),
        catchError((error: any) => {
          // Extract a user-friendly error message
          let errorMessage = 'Registration failed. Please try again.';
          if (error?.error) {
            if (typeof error.error === 'string') {
              errorMessage = error.error;
            } else if (error.error.developerMessage) {
              errorMessage = error.error.developerMessage;
            } else if (error.error.reason) {
              errorMessage = error.error.reason;
            } else if (error.error.message) {
              errorMessage = error.error.message;
            }
          } else if (error?.message) {
            errorMessage = error.message;
          }
          this.notificationService.onError('Registration failed: ' + errorMessage);
          return of({ dataState: DataState.ERROR, registerSuccess: false, error: errorMessage });
        })
      );
  }

  /**
   * Updates the password mismatch flag in real time as the user types.
   * @param registerForm - The registration form reference.
   */
  onPasswordInput(registerForm: NgForm): void {
    const password = registerForm.value.password;
    const confirmPassword = registerForm.value.confirmPassword;
    this.passwordMismatch = password && confirmPassword && password !== confirmPassword;
  }

  /**
   * Resets the registration state to allow creating a new account.
   * Called when the user opts to create another account after a successful registration.
   */
  createAccountForm(): void {
    this.registerState$ = of({ dataState: DataState.LOADED, registerSuccess: false  });
  }
}
