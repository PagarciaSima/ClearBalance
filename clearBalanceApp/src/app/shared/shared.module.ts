import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { UfoComponent } from '../component/ufo/ufo.component';
import {RouterModule } from '@angular/router';
import { PaginationComponent } from '../component/pagination/pagination.component';
import { CapitalizePipe } from '../pipes/capitalize.pipe';
import { CustomerStatusPipe } from '../pipes/customer-status.pipe';

@NgModule({
    declarations: [
      UfoComponent,
      PaginationComponent,
      CapitalizePipe,
      CustomerStatusPipe,
      
    ],
    imports: [
      ReactiveFormsModule,
      CommonModule,
      FormsModule,
      RouterModule
    ],
    exports: [
      ReactiveFormsModule,
      CommonModule,
      FormsModule,
      RouterModule,
      UfoComponent,
      PaginationComponent,
      CapitalizePipe,
      CustomerStatusPipe
      
    ]
})
export class SharedModule { }
