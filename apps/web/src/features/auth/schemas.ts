import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});
export type LoginValues = z.infer<typeof loginSchema>;

// Client-side mirror of profile_validation.normalize_indian_mobile:
// strip whitespace/dashes/parens, then optional +91 / 91 / 0 prefix,
// then 10 digits starting 6-9. Server remains the source of truth
// and returns MOBILE_INVALID on any drift.
const INDIAN_MOBILE = /^(?:\+?91|0)?[6-9]\d{9}$/;
const MOBILE_STRIP = /[\s\-()]/g;

export const indianMobileSchema = z
  .string()
  .min(1, "Mobile number is required")
  .transform((v) => v.replace(MOBILE_STRIP, ""))
  .refine((v) => INDIAN_MOBILE.test(v), "Enter a valid 10-digit Indian mobile number");

export const registerSchema = z.object({
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  email: z.string().email("Enter a valid email address"),
  mobile: indianMobileSchema,
  password: z
    .string()
    .min(12, "At least 12 characters")
    .regex(/[A-Z]/, "Needs an uppercase letter")
    .regex(/[a-z]/, "Needs a lowercase letter")
    .regex(/\d/, "Needs a number")
    .regex(/[^\w\s]/, "Needs a special character"),
  state_code: z.string().min(2, "Select your State / UT"),
  city: z.string().min(1, "Select your city"),
});
export type RegisterValues = z.infer<typeof registerSchema>;

export const mobileOtpRequestSchema = z.object({
  mobile: indianMobileSchema,
});
export type MobileOtpRequestValues = z.infer<typeof mobileOtpRequestSchema>;

export const otpCodeSchema = z.object({
  code: z
    .string()
    .min(6, "Enter the 6-digit code")
    .max(6, "Enter the 6-digit code")
    .regex(/^\d{6}$/, "Code must be 6 digits"),
});
export type OtpCodeValues = z.infer<typeof otpCodeSchema>;

export const emailOtpRequestSchema = z.object({
  email: z.string().email("Enter a valid email address"),
});
export type EmailOtpRequestValues = z.infer<typeof emailOtpRequestSchema>;

export const mfaCodeSchema = z.object({
  code: z.string().min(4, "Enter your authenticator code").max(64),
});
export type MfaCodeValues = z.infer<typeof mfaCodeSchema>;

export const forgotPasswordSchema = z.object({
  email: z.string().email("Enter a valid email address"),
});
export type ForgotPasswordValues = z.infer<typeof forgotPasswordSchema>;

export const resetPasswordSchema = z.object({
  password: z
    .string()
    .min(12, "At least 12 characters")
    .regex(/[A-Z]/, "Needs an uppercase letter")
    .regex(/[a-z]/, "Needs a lowercase letter")
    .regex(/\d/, "Needs a number")
    .regex(/[^\w\s]/, "Needs a special character"),
});
export type ResetPasswordValues = z.infer<typeof resetPasswordSchema>;
