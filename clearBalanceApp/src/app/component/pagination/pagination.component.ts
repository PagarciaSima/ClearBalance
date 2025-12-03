import { Component, Input, Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'app-pagination',
  templateUrl: './pagination.component.html',
  styleUrls: ['./pagination.component.css']
})
export class PaginationComponent {
  @Input() currentPage: number = 1;
  @Input() totalPages: number = 1;
  @Output() pageChange = new EventEmitter<number>();

  get pages(): number[] {
    if (this.totalPages <= 3) {
      return Array.from({ length: this.totalPages }, (_, i) => i + 1);
    }
    if (this.currentPage <= 2) {
      return [1, 2, 3];
    }
    if (this.currentPage >= this.totalPages - 1) {
      return [this.totalPages - 2, this.totalPages - 1, this.totalPages];
    }
    return [this.currentPage - 1, this.currentPage, this.currentPage + 1];
  }

  goToPage(page: number) {
    if (page !== this.currentPage && page > 0 && page <= this.totalPages) {
      this.pageChange.emit(page);
    }
  }

  goToFirst() {
    if (this.currentPage !== 1) {
      this.pageChange.emit(1);
    }
  }

  goToLast() {
    if (this.currentPage !== this.totalPages) {
      this.pageChange.emit(this.totalPages);
    }
  }

  goToPrevious() {
    if (this.currentPage > 1) {
      this.pageChange.emit(this.currentPage - 1);
    }
  }

  goToNext() {
    if (this.currentPage < this.totalPages) {
      this.pageChange.emit(this.currentPage + 1);
    }
  }
}
