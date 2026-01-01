import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { BehaviorSubject, catchError, map, Observable, of, startWith, switchMap } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { User } from 'src/app/interface/user';
import { AccountType, VerifyState } from 'src/app/interface/verifyState';
import { UserService } from 'src/app/service/user.service';
import { NotificationService } from 'src/app/service/notification.service';

@Component({
  selector: 'app-verify',
  templateUrl: './verify.component.html',
  styleUrls: ['./verify.component.css'],
  animations: [
    slideBlur
  ]
})
export class VerifyComponent implements OnInit {
  showPassword = false;
  showConfirmPassword = false;

  verifyState$: Observable<VerifyState> = of();
  private userSubject = new BehaviorSubject<User | null>(null);
  user$ = this.userSubject.asObservable();
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;
  private readonly ACCOUNT_KEY: string = 'key';

  constructor(
    private activatedRoute: ActivatedRoute,
    private userService: UserService,
    private notificationService: NotificationService
  ) { }

  ngOnInit(): void {
    this.verifyPasswordOrAccount();
  }

  /**
   * Verifies the account or password based on the route parameters.
   * Sets the verifyState$ observable with the verification result.
   */
  private verifyPasswordOrAccount() {
    this.verifyState$ = this.activatedRoute.paramMap.pipe(
      switchMap((params: ParamMap) => {
        const type: AccountType = this.getVerificationType(window.location.href);
        const key = params.get(this.ACCOUNT_KEY) ?? '';
        return this.userService.verifyAccountOrPassword$(key, type)
          .pipe(
            map(response => {
              if (type === 'password' && response.data && response.data.user) {
                this.userSubject.next(response.data.user);
              }
              this.notificationService.onSuccess('Verification successful!');
              return { type, title: 'Verified!', dataState: DataState.LOADED, message: response.message ?? '', verifySuccess: true };
            }),
            startWith({ title: 'Verifying...', dataState: DataState.LOADING, message: 'Please wait while we verify the information', verifySuccess: false }),
            catchError((error: any) => {
              let errorMsg = 'Verification failed.';
              if (error && error.error) {
                if (typeof error.error === 'string') {
                  errorMsg = error.error;
                } else if (typeof error.error === 'object') {
                  errorMsg = error.error.reason || error.error.developerMessage || error.message || JSON.stringify(error.error);
                }
              } else if (error && error.message) {
                errorMsg = error.message;
              }
              this.notificationService.onError('Verification failed: ' + errorMsg);
              return of({ title: 'Error', dataState: DataState.ERROR, error: errorMsg, message: errorMsg, verifySuccess: false });
            })
          );
      })
    );
  }

  /**
   * Renews the user's password using the provided form.
   * @param resetPasswordform - The form containing the new password details.
   */
  renewPassword(resetPasswordform: NgForm): void {
    this.isLoadingSubject.next(true);
    this.verifyState$ = this.userService.renewPassword$({ userId: this.userSubject.value?.id ?? 0, password: resetPasswordform.value.password, confirmPassword: resetPasswordform.value.confirmPassword })
      .pipe(
        map(response => {
          console.log(response);
          this.isLoadingSubject.next(false);
          this.notificationService.onSuccess('Password changed successfully! You can now log in.');
          return { type: 'account' as AccountType, title: 'Success', dataState: DataState.LOADED, message: response.message ?? '', verifySuccess: true };
        }),
        startWith({ type: 'password' as AccountType, title: 'Verified!', dataState: DataState.LOADED, verifySuccess: false }),
        catchError((error: any) => {
          console.log("error renewing password:", error);
          let errorMsg = 'Password change failed.';
          if (error && error.error) {
            if (typeof error.error === 'string') {
              errorMsg = error.error;
            } else if (typeof error.error === 'object') {
              errorMsg = error.error.reason || error.error.developerMessage || error.message || JSON.stringify(error.error);
            }
          } else if (error && error.message) {
            errorMsg = error.message;
          }
          this.isLoadingSubject.next(false);
          this.notificationService.onError('Password change failed: ' + errorMsg);
          return of({ type: 'password' as AccountType, title: 'Verified!', dataState: DataState.LOADED, error: errorMsg, verifySuccess: true })
        })
      )
  }

  /**
   * Determines the verification type based on the current URL.
   * @param url - The current URL.
   * @returns 'password' if the URL contains 'password', otherwise 'account'.
   */
  private getVerificationType(url: string): AccountType {
    return url.includes('password') ? 'password' : 'account';
  }

  /**
 * Returns the email of the current user or an empty string if not available.
 * Used for accessibility in password reset forms.
 */
  getUserEmail(): string {
    const user = this.userSubject.value;
    return user && user.email ? user.email : '';
  }

  /**
   * Toggles the visibility of the new password field.
   */
  togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  /**
   * Toggles the visibility of the confirm password field.
   */
  toggleConfirmPasswordVisibility(): void {
    this.showConfirmPassword = !this.showConfirmPassword;
  }
}
