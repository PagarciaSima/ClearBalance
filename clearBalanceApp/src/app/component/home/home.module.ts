import { NgModule } from '@angular/core';
import { CoreModule } from 'src/app/core/core.module';
import { SharedModule } from '../shared/shared.module';
import { HomeRoutingModule } from './home-routing.module';
import { HomeComponent } from './home/home.component';
import { StatsComponent } from './stats/stats.component';

/**
 * HomeModule encapsulates the Home and Stats components.
 * Use this module for all features related to the Home section.
 */
@NgModule({
    declarations: [
        HomeComponent,
        StatsComponent
    ],
    imports: [
        CoreModule,
        SharedModule,
        HomeRoutingModule
    ],
    exports: [
        HomeComponent
    ]
})
export class HomeModule { }
