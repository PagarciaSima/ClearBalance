import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NewinvoiceComponent } from './newinvoice.component';

describe('NewinvoiceComponent', () => {
  let component: NewinvoiceComponent;
  let fixture: ComponentFixture<NewinvoiceComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NewinvoiceComponent]
    });
    fixture = TestBed.createComponent(NewinvoiceComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
