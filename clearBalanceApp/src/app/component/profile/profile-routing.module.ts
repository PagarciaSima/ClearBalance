import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { ProfileComponent } from './profile/profile.component';

/**
 * Defines the routes for the ProfileModule.
 * The ProfileComponent is the default route for this module.
 */
const routes: Routes = [
  {
    path: '',
    component: ProfileComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class ProfileRoutingModule {}
