import { Component } from '@angular/core';
import { slideBlur } from 'src/app/animations/animations';

@Component({
  selector: 'app-customers',
  templateUrl: './customers.component.html',
  styleUrls: ['./customers.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomersComponent {

}
