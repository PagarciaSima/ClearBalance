import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { CapitalizePipe } from '../../pipes/capitalize.pipe';
import { CustomerStatusPipe } from '../../pipes/customer-status.pipe';
import { EventTypeFormatPipe } from 'src/app/pipes/event-type-format.pipe';
import { FooterComponent } from './footer/footer.component';
import { NavbarComponent } from './navbar/navbar.component';
import { PageNotFoundComponent } from './page-not-found/page-not-found.component';
import { PaginationComponent } from './pagination/pagination.component';
import { ShootingStarComponent } from './shooting-star/shooting-star.component';
import { UfoComponent } from './ufo/ufo.component';

@NgModule({
  declarations: [
    CapitalizePipe,
    CustomerStatusPipe,
    EventTypeFormatPipe,
    FooterComponent,
    NavbarComponent,
    PageNotFoundComponent,
    PaginationComponent,
    ShootingStarComponent,
    UfoComponent
  ],
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    RouterModule
  ],
  exports: [
    CapitalizePipe,
    CommonModule,
    CustomerStatusPipe,
    EventTypeFormatPipe,
    FooterComponent,
    FormsModule,
    NavbarComponent,
    PageNotFoundComponent,
    PaginationComponent,
    ReactiveFormsModule,
    RouterModule,
    ShootingStarComponent,
    UfoComponent
  ]
})
export class SharedModule { }
