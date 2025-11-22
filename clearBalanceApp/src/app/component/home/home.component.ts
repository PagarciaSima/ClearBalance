import { Component, AfterViewInit, OnDestroy } from '@angular/core';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements AfterViewInit, OnDestroy {

  constructor(private tooltipService: TooltipService) {}

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  ngOnDestroy(): void {
    this.tooltipService.hideAll();
  }

  report() {
    throw new Error('Method not implemented.');
  }
}
