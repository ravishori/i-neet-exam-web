"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "@/lib/api-client";
import { authApi, isMfaChallenge, type MeResponse } from "@/features/auth/api";

export const ME_QUERY_KEY = ["auth", "me"] as const;

export function useMe() {
  return useQuery({
    queryKey: ME_QUERY_KEY,
    queryFn: authApi.me,
    retry: false, // 401 means "logged out", not "try again"
    staleTime: 60_000,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.login,
    onSuccess: (result) => {
      // MFA challenge is not a session — don't poison the "me" cache with it.
      if (!isMfaChallenge(result)) queryClient.setQueryData(ME_QUERY_KEY, result);
    },
  });
}

export function useMfaVerify() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.mfaVerify,
    onSuccess: (user: MeResponse) => queryClient.setQueryData(ME_QUERY_KEY, user),
  });
}

export function useMobileOtpSend() {
  return useMutation({ mutationFn: authApi.mobileOtpSend });
}

export function useMobileOtpVerify() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.mobileOtpVerify,
    onSuccess: (user: MeResponse) => queryClient.setQueryData(ME_QUERY_KEY, user),
  });
}

export function useEmailOtpRequest() {
  return useMutation({ mutationFn: authApi.emailOtpRequest });
}

export function useEmailOtpVerify() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.emailOtpVerify,
    onSuccess: (user: MeResponse) => queryClient.setQueryData(ME_QUERY_KEY, user),
  });
}

export function useRegister() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.register,
    onSuccess: (user) => queryClient.setQueryData(ME_QUERY_KEY, user),
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: authApi.logout,
    onSuccess: () => queryClient.setQueryData(ME_QUERY_KEY, null),
  });
}

export { ApiError };
