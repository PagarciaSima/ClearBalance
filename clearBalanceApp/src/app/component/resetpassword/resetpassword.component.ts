import { Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Observable, of, map, startWith, catchError } from 'rxjs';
import { DataState } from 'src/app/enum/datastate.enum';
import { RegisterState } from 'src/app/interface/registerState';
import { ResetPasswordState } from 'src/app/interface/resetPasswordState';
import { TooltipService } from 'src/app/service/tooltip.service';
import { UserService } from 'src/app/service/user.service';

@Component({
  selector: 'app-resetpassword',
  templateUrl: './resetpassword.component.html',
  styleUrls: ['./resetpassword.component.css']
})
export class ResetpasswordComponent {

resetPasswordState$: Observable<ResetPasswordState> = of({ dataState: DataState.LOADED });
readonly DataState = DataState;

constructor(private userService: UserService) {}

resetPassword(resetPasswordForm: NgForm): void {
  this.resetPasswordState$ = this.userService.requestPasswordReset$(resetPasswordForm.value.email)
    .pipe(
      map(response => {
        console.log(response);
        resetPasswordForm.reset();
        return { dataState: DataState.LOADED, registerSuccess: true, message: response.message };
      }),
      startWith({ dataState: DataState.LOADING, registerSuccess: false }),
      catchError((error: any) => {
         // Extract a user-friendly error message
          let errorMessage = 'Registration failed.';
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
          return of({ dataState: DataState.ERROR, registerSuccess: false, error: errorMessage })
      })
    );
}
}
