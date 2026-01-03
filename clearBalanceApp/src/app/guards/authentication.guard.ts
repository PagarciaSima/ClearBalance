import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { UserService } from '../service/user.service';

/**
 * Guard to protect routes that require authentication.
 * If the user is not authenticated, they are redirected to the login page.
 * @returns A boolean indicating whether the route can be activated (true) or not (false)
 */
export const authenticationGuard: CanActivateFn = (route, state) => {
  const userService = inject(UserService);
  const router = inject(Router);
  if (userService.isAuthenticated()) {
    return true;
  } else {
    router.navigate(['/auth/login']);
    return false;
  }
};
