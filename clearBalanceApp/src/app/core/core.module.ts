import { NgModule } from '@angular/core';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { CacheInterceptor } from 'src/app/interceptor/cache.interceptor';
import { TokenInterceptor } from 'src/app/interceptor/token.interceptor';
import { UserService } from 'src/app/service/user.service';
import { CustomerService } from 'src/app/service/customer.service';
import { EventService } from 'src/app/service/event.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { CacheService } from 'src/app/service/cache.service';

@NgModule({
  providers: [
    UserService,
    CustomerService,
    EventService,
    TooltipService,
    CacheService,
    {
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: CacheInterceptor,
      multi: true
    }
  ]
})
export class CoreModule { }
