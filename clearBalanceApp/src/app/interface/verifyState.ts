import { DataState } from "../enum/datastate.enum";

export interface VerifyState {
  dataState: DataState;
  verifySuccess?: boolean;
  error?: string;
  message?: string;
  title?: string;
  type?: AccountType;
}

export type AccountType = 'account' | 'password';