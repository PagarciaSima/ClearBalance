import { CustomerStatusPipe } from './customer-status.pipe';

describe('CustomerStatusPipe', () => {
  it('create an instance', () => {
    const pipe = new CustomerStatusPipe();
    expect(pipe).toBeTruthy();
  });
});
