import { NgModule } from '@angular/core';
import { RouterModule, Routes, PreloadAllModules } from '@angular/router';
import { PageNotFoundComponent } from './component/shared/page-not-found/page-not-found.component';
import { authenticationGuard } from './guards/authentication.guard';

/**
 *  set up the routes for the application
 */
const routes: Routes = [
  { path: 'profile', loadChildren: () => import('./component/profile/profile.module').then(m => m.ProfileModule), canActivate: [authenticationGuard] },
  { path: 'invoices', loadChildren: () => import('./component/invoice/invoice.module').then(m => m.InvoiceModule), canActivate: [authenticationGuard] },
  { path: 'customers', loadChildren: () => import('./component/customer/customer.module').then(m => m.CustomerModule), canActivate: [authenticationGuard] },
  { path: '', redirectTo: 'home', pathMatch: 'full' },
  { path: 'home', loadChildren: () => import('./component/home/home.module').then(m => m.HomeModule), canActivate: [authenticationGuard] },
  { path: '**', component: PageNotFoundComponent},
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, { preloadingStrategy: PreloadAllModules })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule { }
