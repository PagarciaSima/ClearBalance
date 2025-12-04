import { EventType } from '../enum/event-type.enum';

export interface Sort {
  empty: boolean;
  sorted: boolean;
  unsorted: boolean;
}

export interface Pageable {
  pageNumber: number;
  pageSize: number;
  sort: Sort;
  offset: number;
  unpaged: boolean;
  paged: boolean;
}

export interface Events {
  id: number;
  type: EventType;
  description: string;
  device: string;
  ipAddress: string;
  createdAt: Date;
}

export interface PagedEvents {
  content: Events[];
  pageable: Pageable;
  last: boolean;
  totalElements: number;
  totalPages: number;
  numberOfElements: number;
  first: boolean;
  size: number;
  number: number;
  sort: Sort;
  empty: boolean;
}

export interface EventsData {
  events: PagedEvents;
}