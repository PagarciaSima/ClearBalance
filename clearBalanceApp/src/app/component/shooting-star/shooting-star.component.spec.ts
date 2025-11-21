import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ShootingStarComponent } from './shooting-star.component';

describe('ShootingStarComponent', () => {
  let component: ShootingStarComponent;
  let fixture: ComponentFixture<ShootingStarComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ShootingStarComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ShootingStarComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
