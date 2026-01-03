import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CustomersMapComponent } from './customers-map.component';

describe('CustomersMapComponent', () => {
  let component: CustomersMapComponent;
  let fixture: ComponentFixture<CustomersMapComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CustomersMapComponent]
    });
    fixture = TestBed.createComponent(CustomersMapComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
