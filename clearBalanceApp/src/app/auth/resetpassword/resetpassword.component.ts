import { Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { catchError, map, Observable, of, startWith } from 'rxjs';
import { DataState } from 'src/app/enum/datastate.enum';
import { ResetPasswordState } from 'src/app/interface/resetPasswordState';
import { UserService } from 'src/app/service/user.service';
import { NotificationService } from 'src/app/service/notification.service';

@Component({
  selector: 'app-resetpassword',
  templateUrl: './resetpassword.component.html',
  styleUrls: ['./resetpassword.component.css']
})
export class ResetpasswordComponent {

resetPasswordState$: Observable<ResetPasswordState> = of({ dataState: DataState.LOADED });
readonly DataState = DataState;

constructor(private userService: UserService, private notificationService: NotificationService) {}

  /**
   * Initiates the password reset process using the provided form.
   * @param resetPasswordForm - The form containing the user's email for password reset.
   */
resetPassword(resetPasswordForm: NgForm): void {
  this.resetPasswordState$ = this.userService.requestPasswordReset$(resetPasswordForm.value.email)
    .pipe(
      map(response => {
        console.log(response);
        resetPasswordForm.reset();
        this.notificationService.onSuccess('Password reset email sent successfully! Please check your inbox.');
        return { dataState: DataState.LOADED, registerSuccess: true, message: response.message };
      }),
      startWith({ dataState: DataState.LOADING, registerSuccess: false }),
      catchError((error: any) => {
         // Extract a user-friendly error message
          let errorMessage = 'Password reset failed. Please try again.';
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
          this.notificationService.onError('Password reset failed: ' + errorMessage);
          return of({ dataState: DataState.ERROR, registerSuccess: false, error: errorMessage })
      })
    );
}
}
