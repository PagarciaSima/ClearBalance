import { Component, Input, Output, EventEmitter } from '@angular/core';
import { UserEventReportDetailDto } from 'src/app/interface/userEventReportResponse';

@Component({
  selector: 'app-report-detail-modal',
  templateUrl: './report-detail-modal.component.html',
  styleUrls: ['./report-detail-modal.component.css']
})
export class ReportDetailModalComponent {
  @Input() selectedReportDetail: UserEventReportDetailDto | null = null;
  @Output() closeModal = new EventEmitter<void>();

  onClose() {
    this.closeModal.emit();
  }
}
