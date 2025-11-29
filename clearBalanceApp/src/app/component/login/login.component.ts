import { Component, AfterViewInit, OnDestroy } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
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
export class LoginComponent implements AfterViewInit, OnDestroy {

  loginState$: Observable<LoginState> = of({ dataState: DataState.LOADED});
  private phoneSubject = new BehaviorSubject<string | null>(null);
  private emailSubject = new BehaviorSubject<string | null>(null);
  readonly DataState = DataState;
  showPassword = false;

  constructor(
    private router: Router,
    private userService: UserService,
    private tooltipService: TooltipService
  ) {}

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  ngOnDestroy(): void {
    this.tooltipService.hideAll();
  }

  /**
   * Handles the login process by invoking the authentication service,
   * mapping the server response into a UI-friendly login state, and 
   * updating the component observable (loginState$) consumed by the template.
   *
   * @param loginForm - Angular form containing user credentials (email & password).
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
   * Processes the login response and determines the appropriate state based on MFA requirements.
   * 
   * @param response - The HTTP response from the login service containing user data and tokens.
   * @returns A LoginState object indicating whether MFA is required or login was successful.
   * 
   * @remarks
   * If MFA is enabled for the user:
   * - Stores phone and email in BehaviorSubjects for later verification
   * - Returns a state with MFA flag and masked phone number
   * 
   * If MFA is not enabled:
   * - Stores JWT tokens in localStorage
   * - Navigates to the home page
   * - Returns a success state
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
   * 
   * @param response - The HTTP response containing user data with MFA enabled.
   * @returns A LoginState object with MFA flag and masked phone number.
   */
  private handleMfaRequired(response: any): LoginState {
    this.phoneSubject.next(response.data.user.phone ?? null);
    this.emailSubject.next(response.data.user.email ?? null);
    
    // Reinitialize tooltips after view updates for MFA screen
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
   * 
   * @param response - The HTTP response containing access and refresh tokens.
   * @returns A LoginState object indicating successful login.
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
   * Handles the verification of the multi-factor authentication (MFA) code.
   * Invokes the user service to verify the provided code and updates the login state accordingly.
   *
   * @param verifyCodeForm - Angular form containing the MFA verification code.
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
   * Handles successful MFA code verification by storing tokens and navigating to home.
   * 
   * @param response - The HTTP response containing access and refresh tokens after successful verification.
   * @returns A LoginState object indicating successful login.
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
   * 
   * @returns A LoginState object with loading state and masked phone number.
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
   * 
   * @param error - The error message to display.
   * @param withMfa - Whether the error occurred during MFA verification.
   * @returns A LoginState object with error state and optional masked phone number.
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
   * 
   * @param accessToken - The JWT access token.
   * @param refreshToken - The JWT refresh token.
   */
  private storeTokens(accessToken?: string, refreshToken?: string): void {
    localStorage.setItem(Key.TOKEN, accessToken ?? '');
    localStorage.setItem(Key.REFRESH_TOKEN, refreshToken ?? '');
  }

  /**
   * Returns the last 4 digits of a phone number for display purposes.
   * 
   * @param phone - The full phone number.
   * @returns The last 4 digits of the phone number, or undefined if phone is null.
   */
  private getMaskedPhone(phone: string | null | undefined): string | undefined {
    return phone?.substring(phone.length - 4);
  }

  /**
   * Resets the login state to show the initial login page.
   * This method is typically called when the user opts to return to the login form
   * from the MFA verification step.
   */
  loginPage(): void {
    this.loginState$ = of({ dataState: DataState.LOADED });
    // Reinitialize tooltips after view returns to login screen
    setTimeout(() => {
      this.tooltipService.hideAll();
      this.tooltipService.initialize();
    }, 100);
  }

}
