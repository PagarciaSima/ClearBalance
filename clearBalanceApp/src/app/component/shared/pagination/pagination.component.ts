import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';

@Component({
    selector: 'app-pagination',
    templateUrl: './pagination.component.html',
    styleUrls: ['./pagination.component.css'],
    changeDetection: ChangeDetectionStrategy.OnPush
})
export class PaginationComponent {
    @Input() currentPage: number = 1;
    @Input() totalPages: number = 1;
    @Input() pageSize: number = 10;
    @Input() pageSizeOptions: number[] = [5, 10, 20];
    /**
     * Total number of items in the dataset (for display).
     */
    @Input() totalItems: number = 0;
    @Output() pageChange = new EventEmitter<number>();
    @Output() pageSizeChange = new EventEmitter<number>();

    /**
     *  Manages the change event from the page size select element
     */
    handlePageSizeChange(event: Event): void {
        const value = (event.target as HTMLSelectElement)?.value;
        if (value) {
            this.onPageSizeChange(Number(value));
        }
    }

    /**
     * Called when the user changes the page size
     */
    onPageSizeChange(newSize: number): void {
        this.pageSizeChange.emit(newSize);
    }

    /**
   * Generates an array of consecutive numbers from a starting value to an ending value (inclusive).
   *
   * @param from - The first number in the generated range.
   * @param to - The last number in the generated range.
   * @returns An array of numbers from `from` to `to`.
   */
    private range(from: number, to: number): number[] {
        const arr = [];
        // Push every number between 'from' and 'to' (inclusive)
        for (let i = from; i <= to; i++) arr.push(i);
        return arr;
    }

    /**
     * Computes the set of page numbers to display in the pagination control.
     * <p>
     * The logic adapts based on the total number of pages and the user's current page:
     * - If there are 3 or fewer pages, all pages are shown.
     * - If the user is on the first two pages, the first 3 pages are shown.
     * - If the user is on the last two pages, the last 3 pages are shown.
     * - Otherwise, a sliding window of three pages centered around the current page is shown.
     * </p>
     *
     * @returns An array of page numbers to display.
     */
    get pages(): number[] {
        // Case 1: Show all pages if there are 3 or fewer
        if (this.totalPages <= 3) {
            return this.range(1, this.totalPages);
        }

        // Case 2: User is at the beginning → show pages 1–3
        if (this.currentPage <= 2) {
            return this.range(1, 3);
        }

        // Case 3: User is near the end → show last 3 pages
        if (this.currentPage >= this.totalPages - 1) {
            return this.range(this.totalPages - 2, this.totalPages);
        }

        // Case 4: User is in the middle → show previous, current, and next page
        return this.range(this.currentPage - 1, this.currentPage + 1);
    }

    /**
     * Navigates to the specified page if it's different from the current page
     * and within valid bounds.
     *
     * @param page - The page number to navigate to.
     */
    goToPage(page: number): void {
        if (page !== this.currentPage && page > 0 && page <= this.totalPages) {
            this.pageChange.emit(page);
        }
    }

    /**
     * Navigates to the first page if not already on it.
     */
    goToFirst(): void {
        if (this.currentPage !== 1) {
            this.pageChange.emit(1);
        }
    }

    /**
     * Navigates to the last page if not already on it.
     */
    goToLast(): void {
        if (this.currentPage !== this.totalPages) {
            this.pageChange.emit(this.totalPages);
        }
    }

    /**
     * Navigates to the previous page if not already on the first page.
     */
    goToPrevious(): void {
        if (this.currentPage > 1) {
            this.pageChange.emit(this.currentPage - 1);
        }
    }

    /**
     * Navigates to the next page if not already on the last page.
     */
    goToNext(): void {
        if (this.currentPage < this.totalPages) {
            this.pageChange.emit(this.currentPage + 1);
        }
    }
}
