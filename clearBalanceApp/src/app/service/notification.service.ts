import { Injectable } from '@angular/core';
import Swal from 'sweetalert2/dist/sweetalert2.all.js';

@Injectable({ providedIn: 'root' })
export class NotificationService {
  private galacticOptions = {
    customClass: {
      popup: 'swal-galactic-popup',
      title: 'swal-galactic-title',
      confirmButton: 'swal-galactic-confirm',
      cancelButton: 'swal-galactic-cancel'
    },
    background: 'linear-gradient(135deg, #220d46 0%, #3d185e 50%, #1e3a5f 100%)',
    color: '#fff',
    showConfirmButton: true,
    confirmButtonColor: '#5d42e6',
    cancelButtonColor: '#d32985'
  };

  showSuccess(message: string, title: string = '¡Éxito Galáctico!') {
    Swal.fire({
      ...this.galacticOptions,
      icon: 'success',
      title,
      text: message,
      timer: 2500,
      showConfirmButton: false
    });
  }

  showError(message: string, title: string = '¡Error Interestelar!') {
    Swal.fire({
      ...this.galacticOptions,
      icon: 'error',
      title,
      text: message
    });
  }

  showWarning(message: string, title: string = '¡Alerta Cósmica!') {
    Swal.fire({
      ...this.galacticOptions,
      icon: 'warning',
      title,
      text: message
    });
  }

  showInfo(message: string, title: string = 'Dato Galáctico') {
    Swal.fire({
      ...this.galacticOptions,
      icon: 'info',
      title,
      text: message
    });
  }

  confirm(message: string, title: string = '¿Estás seguro?'): Promise<boolean> {
    return Swal.fire({
      ...this.galacticOptions,
      title,
      text: message,
      icon: 'question',
      showCancelButton: true,
      confirmButtonText: 'Sí',
      cancelButtonText: 'No'
    }).then((result: any) => result.isConfirmed);
  }
}
