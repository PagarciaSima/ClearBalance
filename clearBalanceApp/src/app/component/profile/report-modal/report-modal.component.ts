import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';
import { FormGroup } from '@angular/forms';

@Component({
  selector: 'app-report-modal',
  templateUrl: './report-modal.component.html',
  styleUrls: ['./report-modal.component.css'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ReportModalComponent {
  @Input() reportForm!: FormGroup;
  @Input() loading: boolean = false;
  @Output() submitReport = new EventEmitter<void>();
  @Output() closeModal = new EventEmitter<void>();
}
