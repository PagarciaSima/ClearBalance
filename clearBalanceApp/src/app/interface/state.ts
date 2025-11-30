import { DataState } from "../enum/datastate.enum";

export interface State<T> {
  dataState: DataState;
  appData?: T | null;
  error?: string;
}