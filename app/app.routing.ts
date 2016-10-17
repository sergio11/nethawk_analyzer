import { AuthGuard } from "./guards/auth-guard.service";

export const authProviders = [
  AuthGuard
];

export const appRoutes = [
  { path: "", redirectTo: "/groceries", pathMatch: "full" }
];