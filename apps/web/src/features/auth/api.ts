import { apiClient } from "@/lib/api-client";

export type MeResponse = {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  display_name: string | null;
  email_verified: boolean;
  roles: string[];
  totp_enabled?: boolean;
  must_change_password?: boolean;
  mobile_e164?: string | null;
  state_code?: string | null;
  city_name?: string | null;
  // Non-blocking password-age reminder — see backend PASSWORD_MAX_AGE_DAYS.
  // `password_age_days` is null for legacy accounts with unknown password
  // history; clients must NOT nag in that case.
  password_age_days?: number | null;
  password_reminder_due?: boolean;
};

export type RegisterPayload = {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  mobile: string;
  state_code: string;
  city: string;
};

export type StateOption = { id: string; code: string; name: string };
export type CityOption = { id: string; name: string };

// Never claim a login method works when its provider isn't configured —
// the login UI must only show tabs the backend actually reports available.
export type AuthMethods = {
  emailPassword: boolean;
  mobileOtp: boolean;
  emailOtp: boolean;
  google: boolean;
  microsoft: boolean;
};

// Password login can short-circuit into a TOTP step-up challenge instead of
// a session — mirrors auth_router.login's {"mfaRequired": true, "mfaToken"}
// branch.
export type LoginResult = MeResponse | { mfaRequired: true; mfaToken: string; email: string };

function isMfaChallenge(result: LoginResult): result is { mfaRequired: true; mfaToken: string; email: string } {
  return (result as { mfaRequired?: boolean }).mfaRequired === true;
}

export const authApi = {
  me: () => apiClient.get<MeResponse>("/api/v1/auth/me"),
  methods: () => apiClient.get<AuthMethods>("/api/v1/auth/methods"),
  login: (data: { email: string; password: string }) =>
    apiClient.post<LoginResult>("/api/v1/auth/login", data),
  register: (data: RegisterPayload) =>
    apiClient.post<MeResponse>("/api/v1/auth/register", data),
  logout: () => apiClient.post<{ loggedOut: boolean }>("/api/v1/auth/logout"),
  forgotPassword: (data: { email: string }) =>
    apiClient.post<{ message: string }>("/api/v1/auth/forgot-password", data),
  resetPassword: (data: { token: string; new_password: string }) =>
    apiClient.post<{ message: string }>("/api/v1/auth/reset-password", data),
  verifyEmail: (data: { token: string }) =>
    apiClient.post<MeResponse>("/api/v1/auth/verify-email", data),
  mfaVerify: (data: { mfa_token: string; code: string }) =>
    apiClient.post<MeResponse>("/api/v1/auth/mfa/verify", data),
  mobileOtpSend: (data: { mobile: string }) =>
    apiClient.post<{ message: string; channel: string }>("/api/v1/auth/mobile/otp/send", data),
  mobileOtpVerify: (data: { mobile: string; code: string }) =>
    apiClient.post<MeResponse>("/api/v1/auth/mobile/otp/verify", data),
  emailOtpRequest: (data: { email: string }) =>
    apiClient.post<{ message: string }>("/api/v1/auth/otp/request", { ...data, purpose: "email_login" }),
  emailOtpVerify: (data: { email: string; code: string }) =>
    apiClient.post<LoginResult>("/api/v1/auth/otp/verify", { ...data, purpose: "email_login" }),
};

export { isMfaChallenge };

export const locationsApi = {
  listStates: () => apiClient.get<StateOption[]>("/api/v1/locations/states"),
  listCitiesForState: (stateId: string) =>
    apiClient.get<CityOption[]>(`/api/v1/locations/states/${stateId}/cities`),
};
