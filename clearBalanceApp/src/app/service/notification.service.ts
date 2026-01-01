import { Injectable } from '@angular/core';
import { NotifierService } from 'angular-notifier';

enum Type {
  DEFAULT = 'default',
  INFO = 'info',
  SUCCESS = 'success',
  WARNING = 'warning',
  ERROR = 'error'
}

@Injectable({ providedIn: 'root' })
export class NotificationService {

  constructor(private notifierService: NotifierService) { }

  /**
   * Displays a notification of the specified type with the given message.
   */
  onDefault(message: string): void {
    this.notifierService.notify(Type.DEFAULT, message);
  }

  /**
   * Displays a success notification with the given message.
   */
  onSuccess(message: string): void {
    this.notifierService.notify(Type.SUCCESS, message);
  }

  /**
   * Displays an info notification with the given message.
   */
  onInfo(message: string): void {
    this.notifierService.notify(Type.INFO, message);
  }

  /**
   * Displays a warning notification with the given message.
   */
  onWarning(message: string): void {
    this.notifierService.notify(Type.WARNING, message);
  }

  /**
   * Displays an error notification with the given message.
   */
  onError(message: string): void {
    this.notifierService.notify(Type.ERROR, message);
  }

}
