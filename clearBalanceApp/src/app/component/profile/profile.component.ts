import { Component, AfterViewInit, OnDestroy } from '@angular/core';
import { NgForm } from '@angular/forms';
import { TooltipService } from 'src/app/service/tooltip.service';
import { slideBlur } from 'src/app/animations/animations';

declare var bootstrap: any;

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css'],
  animations: [
    slideBlur
  ]
})
export class ProfileComponent implements AfterViewInit, OnDestroy {

  private tooltipInstances: any[] = [];

  constructor(private tooltipService: TooltipService) {}

  ngAfterViewInit(): void {
    // Small delay to ensure DOM is ready
    setTimeout(() => {
      // Initialize regular tooltips (non-pill buttons)
      this.tooltipService.initialize();
      
      // Initialize tooltips for pill buttons manually
      this.initializePillTooltips();
    }, 150);
  }

  ngOnDestroy(): void {
    this.tooltipService.hideAll();
    this.disposePillTooltips();
  }

  private initializePillTooltips(): void {
    const pillButtons = document.querySelectorAll('[data-bs-toggle="pill"][title]');
    pillButtons.forEach((element: any) => {
      // Dispose any existing tooltip first
      const existingTooltip = bootstrap.Tooltip.getInstance(element);
      if (existingTooltip) {
        existingTooltip.dispose();
      }
      
      const tooltip = new bootstrap.Tooltip(element, {
        placement: element.getAttribute('data-bs-placement') || 'top',
        trigger: 'hover',
        animation: false,
        delay: { show: 500, hide: 0 }
      });
      this.tooltipInstances.push(tooltip);
    });
  }

  private disposePillTooltips(): void {
    this.tooltipInstances.forEach(tooltip => {
      tooltip.dispose();
    });
    this.tooltipInstances = [];
  }

updateAccountSettings(_t149: NgForm) {
throw new Error('Method not implemented.');
}
updateRole(_t125: NgForm) {
throw new Error('Method not implemented.');
}
updatePassword(_t85: NgForm) {
throw new Error('Method not implemented.');
}
updateProfile(_t43: NgForm) {
throw new Error('Method not implemented.');
}
toggleMfa() {
throw new Error('Method not implemented.');
}
  // Password visibility toggles
  showCurrentPassword: boolean = false;
  showNewPassword: boolean = false;
  showConfirmPassword: boolean = false;

  // Avatar upload handler
  onAvatarChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files[0]) {
      const file = input.files[0];
      const reader = new FileReader();
      
      reader.onload = (e: ProgressEvent<FileReader>) => {
        // Here you would update the avatar image
        console.log('Avatar selected:', file.name);
        // TODO: Upload to server and update profile
      };
      
      reader.readAsDataURL(file);
    }
  }
}
