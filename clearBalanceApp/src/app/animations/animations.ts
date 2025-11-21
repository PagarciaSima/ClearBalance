import { trigger, transition, style, animate, keyframes } from '@angular/animations';

export const slideIn = trigger('slideIn', [
  transition(':enter', [
    style({ transform: 'translateX(100%)', opacity: 0 }),
    animate('300ms ease-out', style({ transform: 'translateX(0)', opacity: 1 }))
  ])
]);

export const fadeInUp = trigger('fadeInUp', [
    transition(':enter', [
    style({ opacity: 0, transform: 'translateY(20px)' }),
    animate('500ms ease-out', style({ opacity: 1, transform: 'translateY(0)' }))
    ])
]);

// Animación moderna: Scale + Fade (zoom suave)
export const scaleIn = trigger('scaleIn', [
  transition(':enter', [
    style({ transform: 'scale(0.9)', opacity: 0 }),
    animate('400ms cubic-bezier(0.34, 1.56, 0.64, 1)', 
      style({ transform: 'scale(1)', opacity: 1 }))
  ])
]);

// Animación impactante: Flip desde arriba
export const flipIn = trigger('flipIn', [
  transition(':enter', [
    style({ 
      transform: 'perspective(400px) rotateX(-90deg)',
      opacity: 0 
    }),
    animate('600ms cubic-bezier(0.34, 1.56, 0.64, 1)', 
      style({ 
        transform: 'perspective(400px) rotateX(0deg)',
        opacity: 1 
      }))
  ])
]);

// Animación ultra moderna: Bounce + Fade
export const bounceIn = trigger('bounceIn', [
  transition(':enter', [
    animate('800ms cubic-bezier(0.68, -0.55, 0.265, 1.55)', 
      keyframes([
        style({ transform: 'scale(0.3)', opacity: 0, offset: 0 }),
        style({ transform: 'scale(1.05)', opacity: 0.9, offset: 0.5 }),
        style({ transform: 'scale(0.98)', opacity: 1, offset: 0.75 }),
        style({ transform: 'scale(1)', opacity: 1, offset: 1 })
      ])
    )
  ])
]);

// Animación elegante: Slide + Blur
export const slideBlur = trigger('slideBlur', [
  transition(':enter', [
    style({ 
      transform: 'translateY(-30px)', 
      opacity: 0,
      filter: 'blur(10px)' 
    }),
    animate('500ms cubic-bezier(0.4, 0, 0.2, 1)', 
      style({ 
        transform: 'translateY(0)', 
        opacity: 1,
        filter: 'blur(0px)' 
      }))
  ])
]);