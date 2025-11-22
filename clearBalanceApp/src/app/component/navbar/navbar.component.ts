import { Component, AfterViewInit } from '@angular/core';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements AfterViewInit {

  constructor(private tooltipService: TooltipService) {}

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  logOut() {
    throw new Error('Method not implemented.');
  }

}
