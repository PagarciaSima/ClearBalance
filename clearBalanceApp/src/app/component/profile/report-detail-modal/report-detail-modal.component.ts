import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';
import { UserEventReportDetailDto } from 'src/app/interface/userEventReportResponse';

@Component({
  selector: 'app-report-detail-modal',
  templateUrl: './report-detail-modal.component.html',
  styleUrls: ['./report-detail-modal.component.css'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ReportDetailModalComponent {
  @Input() selectedReportDetail: UserEventReportDetailDto | null = null;
  @Output() closeModal = new EventEmitter<void>();

  onClose() {
    this.closeModal.emit();
  }
}
