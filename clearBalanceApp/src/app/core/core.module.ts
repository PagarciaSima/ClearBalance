import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { CacheInterceptor } from 'src/app/interceptor/cache.interceptor';
import { TokenInterceptor } from 'src/app/interceptor/token.interceptor';
import { CacheService } from 'src/app/service/cache.service';
import { CustomerService } from 'src/app/service/customer.service';
import { EventService } from 'src/app/service/event.service';
import { NotificationService } from '../service/notification.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { UserService } from 'src/app/service/user.service';

@NgModule({
  imports: [
    HttpClientModule
  ],
  providers: [
    CacheService,
    CustomerService,
    EventService,
    NotificationService,
    TooltipService,
    UserService,
    {
      provide: HTTP_INTERCEPTORS,
      useClass: CacheInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptor,
      multi: true
    }
  ]
})
export class CoreModule { }
