import { EventType } from '../enum/event-type.enum';
import { Page } from './page';

export interface Events {
  id: number;
  type: EventType;
  description: string;
  device: string;
  ipAddress: string;
  createdAt: Date;
  hasReport?: boolean;
  reportStatus?: string;
}

export interface EventsPage {
  events: Page<Events>;
}