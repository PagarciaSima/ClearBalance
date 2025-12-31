import { NgModule } from '@angular/core';
import { SharedModule } from '../component/shared/shared.module';
import { AuthRoutingModule } from './auth-routing.module';
import { LoginComponent } from './login/login.component';
import { RegisterComponent } from './register/register.component';
import { ResetpasswordComponent } from './resetpassword/resetpassword.component';
import { VerifyComponent } from './verify/verify.component';

@NgModule({
  declarations: [
    LoginComponent,
    RegisterComponent,
    ResetpasswordComponent,
    VerifyComponent,
  ],
  imports: [
    AuthRoutingModule,
    SharedModule,
  ]
})
export class AuthModule { }
