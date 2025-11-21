// filepath: src/main.ts
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from './app/app.module';

declare var particlesJS: any;

platformBrowserDynamic().bootstrapModule(AppModule)
  .then(() => {
    particlesJS('particles-js', {
      particles: {
        number: { value: 80, density: { enable: true, value_area: 800 } },
        color: { value: '#ffffff' },
        shape: { type: 'circle' },
        opacity: { value: 0.5, random: true },
        size: { value: 3, random: true },
        line_linked: {
          enable: true,
          distance: 150,
          color: '#ffffff',
          opacity: 0.4,
          width: 1
        },
        move: { 
          enable: true, 
          speed: 2, 
          direction: 'none', 
          random: false, 
          straight: false,
          out_mode: 'out',
          bounce: false
        }
      },
      interactivity: {
        detect_on: 'canvas',
        events: {
          onhover: { enable: true, mode: 'repulse' },
          onclick: { enable: true, mode: 'push' },
          resize: true
        },
        modes: {
          grab: {
            distance: 200,
            line_linked: { opacity: 1 }
          },
          bubble: {
            distance: 400,
            size: 40,
            duration: 2,
            opacity: 8
          },
          repulse: {
            distance: 100,
            duration: 0.4
          },
          push: { particles_nb: 4 },
          remove: { particles_nb: 2 }
        }
      },
      retina_detect: true
    });
  })
  .catch(err => console.error(err));