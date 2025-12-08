import { Component, AfterViewInit, OnDestroy, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map, startWith } from 'rxjs/operators';
import { DataState } from 'src/app/enum/datastate.enum';
import { Key } from 'src/app/enum/key.enum';
import { LoginState } from 'src/app/interface/appState';
import { UserService } from 'src/app/service/user.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { slideBlur } from 'src/app/animations/animations';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  animations: [
    slideBlur
  ]
})

export class LoginComponent implements AfterViewInit, OnDestroy, OnInit {
  // Public properties
  loginState$: Observable<LoginState> = of({ dataState: DataState.LOADED });
  readonly DataState = DataState;
  showPassword = false;

  // Private properties
  private phoneSubject = new BehaviorSubject<string | null>(null);
  private emailSubject = new BehaviorSubject<string | null>(null);

  // Constructor
  constructor(
    private router: Router,
    private userService: UserService,
    private tooltipService: TooltipService
  ) {}

  // Angular lifecycle hooks
  ngOnInit(): void {
    if (this.userService.isAuthenticated()) {
      this.router.navigate(['/']);
    } else {
      this.router.navigate(['/login']);
    }
  }

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  ngOnDestroy(): void {
    this.tooltipService.hideAll();
  }

  // Public methods
  /**
   * Handles the login process by invoking the authentication service,
   * mapping the server response into a UI-friendly login state, and 
   * updating the component observable (loginState$) consumed by the template.
   */
  login(loginForm: NgForm): void {
    this.loginState$ = this.userService.login$(loginForm.value.email, loginForm.value.password)
      .pipe(
        map(response => this.handleLoginResponse(response)),
        startWith({ dataState: DataState.LOADING, usingMfa: false }),
        catchError((error: string) => of(this.createErrorState(error, false)))
      );
  }

  /**
   * Handles the verification of the multi-factor authentication (MFA) code.
   * Invokes the user service to verify the provided code and updates the login state accordingly.
   */
  verifyCode(verifyCodeForm: NgForm): void {
    this.loginState$ = this.userService.verifyCode$(this.emailSubject.value ?? '', verifyCodeForm.value.code)
      .pipe(
        map(response => this.handleVerificationSuccess(response)),
        startWith(this.createLoadingStateWithMfa()),
        catchError((error: string) => of(this.createErrorState(error, true)))
      );
  }

  /**
   * Resets the login state to show the initial login page.
   * This method is typically called when the user opts to return to the login form
   * from the MFA verification step.
   */
  loginPage(): void {
    this.loginState$ = of({ dataState: DataState.LOADED });
    setTimeout(() => {
      this.tooltipService.hideAll();
      this.tooltipService.initialize();
    }, 100);
  }

  // Private methods
  /**
   * Processes the login response and determines the appropriate state based on MFA requirements.
   */
  private handleLoginResponse(response: any): LoginState {
    if (response?.data?.user?.usingMfa) {
      return this.handleMfaRequired(response);
    } else {
      return this.handleSuccessfulLogin(response);
    }
  }

  /**
   * Handles the case when multi-factor authentication is required.
   */
  private handleMfaRequired(response: any): LoginState {
    this.phoneSubject.next(response.data.user.phone ?? null);
    this.emailSubject.next(response.data.user.email ?? null);
    setTimeout(() => {
      this.tooltipService.hideAll();
      this.tooltipService.initialize();
    }, 100);
    return {
      dataState: DataState.LOADED,
      usingMfa: true,
      loginSuccess: false,
      phone: this.getMaskedPhone(response.data.user.phone)
    };
  }

  /**
   * Handles successful login without MFA by storing tokens and navigating to home.
   */
  private handleSuccessfulLogin(response: any): LoginState {
    this.storeTokens(response?.data?.access_token, response?.data?.refresh_token);
    this.router.navigate(['/']);
    return {
      dataState: DataState.LOADED,
      loginSuccess: true
    };
  }

  /**
   * Handles successful MFA code verification by storing tokens and navigating to home.
   */
  private handleVerificationSuccess(response: any): LoginState {
    this.storeTokens(response?.data?.access_token, response?.data?.refresh_token);
    this.router.navigate(['/']);
    return {
      dataState: DataState.LOADED,
      loginSuccess: true
    };
  }

  /**
   * Creates a loading state for MFA verification process.
   */
  private createLoadingStateWithMfa(): LoginState {
    return {
      dataState: DataState.LOADING,
      usingMfa: true,
      loginSuccess: false,
      phone: this.getMaskedPhone(this.phoneSubject.value)
    };
  }

  /**
   * Creates an error state for login or verification failures.
   */
  private createErrorState(error: any, withMfa: boolean): LoginState {
    let errorMsg = 'Ocurrió un error inesperado.';
    if (error) {
      if (typeof error === 'string') {
        errorMsg = error;
      } else if (error.error && typeof error.error === 'object' && error.error.reason) {
        errorMsg = error.error.reason;
      } else if (error.message) {
        errorMsg = error.message;
      }
    }
    return {
      dataState: DataState.ERROR,
      usingMfa: withMfa,
      loginSuccess: false,
      error: errorMsg,
      ...(withMfa && { phone: this.getMaskedPhone(this.phoneSubject.value) })
    };
  }

  /**
   * Stores JWT access and refresh tokens in localStorage.
   */
  private storeTokens(accessToken?: string, refreshToken?: string): void {
    localStorage.setItem(Key.TOKEN, accessToken ?? '');
    localStorage.setItem(Key.REFRESH_TOKEN, refreshToken ?? '');
  }

  /**
   * Returns the last 4 digits of a phone number for display purposes.
   */
  private getMaskedPhone(phone: string | null | undefined): string | undefined {
    return phone?.substring(phone.length - 4);
  }

}
