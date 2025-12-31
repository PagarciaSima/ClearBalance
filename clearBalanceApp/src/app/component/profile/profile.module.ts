import { NgModule } from '@angular/core';
import { CoreModule } from 'src/app/core/core.module';
import { PermissionFormatPipe } from 'src/app/pipes/permission-format.pipe';
import { RoleFormatPipe } from 'src/app/pipes/role-format.pipe';
import { SharedModule } from '../shared/shared.module';
import { ProfileRoutingModule } from './profile-routing.module';
import { ProfileComponent } from './profile/profile.component';
import { ReportDetailModalComponent } from './report-detail-modal/report-detail-modal.component';
import { ReportModalComponent } from './report-modal/report-modal.component';

/**
 * ProfileModule encapsulates the profile feature and its related modals.
 * Use this module for all profile-related components and features.
 */
@NgModule({
    declarations: [
        PermissionFormatPipe,
        ProfileComponent,
        ReportModalComponent,
        ReportDetailModalComponent,
        RoleFormatPipe,
    ],
    imports: [
        CoreModule,
        ProfileRoutingModule,
        SharedModule,
    ],
    exports: [
        ProfileComponent,
        PermissionFormatPipe,
        RoleFormatPipe,
    ]
})
export class ProfileModule { }
