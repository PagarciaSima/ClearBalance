import { Component } from '@angular/core';
import { slideBlur } from 'src/app/animations/animations';

@Component({
  selector: 'app-customer',
  templateUrl: './customer.component.html',
  styleUrls: ['./customer.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomerComponent {

}
