import { Pipe, PipeTransform } from '@angular/core';
import { EventType } from '../enum/event-type.enum';

interface EventTypeFormat {
    class: string;
    icon: string;
    text: string;
}

@Pipe({
    name: 'eventTypeFormat'
})
export class EventTypeFormatPipe implements PipeTransform {

    private readonly eventTypeMap: { [key: string]: EventTypeFormat } = {
        'LOGIN_ATTEMPT': {
            class: 'bg-secondary',
            icon: 'bi bi-box-arrow-in-right me-2',
            text: 'Login Attempt'
        },
        'LOGIN_ATTEMPT_SUCCESS': {
            class: 'bg-success',
            icon: 'bi bi-check-circle me-2',
            text: 'Login Successful'
        },
        'LOGIN_ATTEMPT_FAILURE': {
            class: 'bg-danger',
            icon: 'bi bi-x-circle me-2',
            text: 'Login Failed'
        },
        'PROFILE_UPDATE': {
            class: 'bg-info',
            icon: 'bi bi-person-lines-fill me-2',
            text: 'Profile Updated'
        },
        'PROFILE_PICTURE_UPDATE': {
            class: 'bg-info',
            icon: 'bi bi-image me-2',
            text: 'Profile Picture Updated'
        },
        'ROLE_UPDATE': {
            class: 'bg-warning',
            icon: 'bi bi-shield-lock me-2',
            text: 'Role Updated'
        },
        'ACCOUNT_SETTINGS_UPDATE': {
            class: 'bg-primary',
            icon: 'bi bi-gear me-2',
            text: 'Account Settings Updated'
        },
        'MFA_UPDATE': {
            class: 'bg-warning',
            icon: 'bi bi-shield-shaded me-2',
            text: 'MFA Updated'
        },
        'PASSWORD_UPDATE': {
            class: 'bg-primary',
            icon: 'bi bi-key me-2',
            text: 'Password Updated'
        }
    };

    private defaultValues(type: string): EventTypeFormat {
        return {
            class: 'bg-secondary',
            icon: 'bi bi-question-circle',
            text: type
        };
    }

    transform(type: EventType | string): EventTypeFormat {
        return this.eventTypeMap[type] || this.defaultValues(type);
    }
}
