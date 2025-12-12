import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'customerStatus'
})
export class CustomerStatusPipe implements PipeTransform {

  transform(status: string): string {
    switch (status) {
      case 'ACTIVE': return 'bg-success';
      case 'PENDING': return 'bg-primary';
      case 'BANNED': return 'bg-danger';
      case 'INACTIVE': return 'bg-warning';
      default: return '';
    }
  }
}
