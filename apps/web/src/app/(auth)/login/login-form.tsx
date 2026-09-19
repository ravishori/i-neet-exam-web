"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError } from "@/lib/api-client";
import { isMfaChallenge } from "@/features/auth/api";
import {
  useAuthMethods,
  useEmailOtpRequest,
  useEmailOtpVerify,
  useLogin,
  useMfaVerify,
  useMobileOtpSend,
  useMobileOtpVerify,
} from "@/features/auth/use-auth";
import {
  emailOtpRequestSchema,
  loginSchema,
  mfaCodeSchema,
  mobileOtpRequestSchema,
  otpCodeSchema,
  type EmailOtpRequestValues,
  type LoginValues,
  type MfaCodeValues,
  type MobileOtpRequestValues,
  type OtpCodeValues,
} from "@/features/auth/schemas";

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Something went wrong";
}

export function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const goToApp = () => router.push(searchParams.get("next") ?? "/student/dashboard");

  // Never claim a login method works when its provider isn't configured —
  // default to email/password only until the backend confirms otherwise.
  const { data: methods } = useAuthMethods();
  const showMobileOtp = methods?.mobileOtp === true;
  const showEmailOtp = methods?.emailOtp === true;

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Sign in</CardTitle>
        <CardDescription>Welcome back to Trinetra.</CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="password">
          <TabsList className="w-full">
            <TabsTrigger value="password">Password</TabsTrigger>
            {showMobileOtp && <TabsTrigger value="mobile">Mobile OTP</TabsTrigger>}
            {showEmailOtp && <TabsTrigger value="email-otp">Email OTP</TabsTrigger>}
          </TabsList>
          <TabsContent value="password">
            <PasswordLogin onDone={goToApp} />
          </TabsContent>
          {showMobileOtp && (
            <TabsContent value="mobile">
              <MobileOtpLogin onDone={goToApp} />
            </TabsContent>
          )}
          {showEmailOtp && (
            <TabsContent value="email-otp">
              <EmailOtpLogin onDone={goToApp} />
            </TabsContent>
          )}
        </Tabs>
        <div className="mt-4 flex justify-between text-sm text-muted-foreground">
          <Link href="/forgot-password" className="hover:underline">
            Forgot password?
          </Link>
          <Link href="/register" className="hover:underline">
            Create account
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

function PasswordLogin({ onDone }: { onDone: () => void }) {
  const login = useLogin();
  const mfaVerify = useMfaVerify();
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginValues>({ resolver: zodResolver(loginSchema) });

  const mfaForm = useForm<MfaCodeValues>({ resolver: zodResolver(mfaCodeSchema) });

  const onSubmit = (values: LoginValues) => {
    login.mutate(values, {
      onSuccess: (result) => {
        if (isMfaChallenge(result)) {
          setMfaToken(result.mfaToken);
        } else {
          onDone();
        }
      },
    });
  };

  const onMfaSubmit = (values: MfaCodeValues) => {
    if (!mfaToken) return;
    mfaVerify.mutate({ mfa_token: mfaToken, code: values.code }, { onSuccess: onDone });
  };

  if (mfaToken) {
    return (
      <form onSubmit={mfaForm.handleSubmit(onMfaSubmit)} className="mt-4 flex flex-col gap-4">
        {mfaVerify.isError && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(mfaVerify.error)}</AlertDescription>
          </Alert>
        )}
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="mfa-code">Authenticator code</Label>
          <Input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" {...mfaForm.register("code")} />
          {mfaForm.formState.errors.code && (
            <p className="text-sm text-destructive">{mfaForm.formState.errors.code.message}</p>
          )}
        </div>
        <Button type="submit" disabled={mfaVerify.isPending} className="mt-2">
          {mfaVerify.isPending ? "Verifying…" : "Verify"}
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="mt-4 flex flex-col gap-4">
      {login.isError && (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(login.error)}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="email">Email</Label>
        <Input id="email" type="email" autoComplete="email" {...register("email")} />
        {errors.email && <p className="text-sm text-destructive">{errors.email.message}</p>}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="password">Password</Label>
        <Input id="password" type="password" autoComplete="current-password" {...register("password")} />
        {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}
      </div>
      <Button type="submit" disabled={login.isPending} className="mt-2">
        {login.isPending ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}

function MobileOtpLogin({ onDone }: { onDone: () => void }) {
  const send = useMobileOtpSend();
  const verify = useMobileOtpVerify();
  const [mobile, setMobile] = useState<string | null>(null);

  const requestForm = useForm<MobileOtpRequestValues>({ resolver: zodResolver(mobileOtpRequestSchema) });
  const codeForm = useForm<OtpCodeValues>({ resolver: zodResolver(otpCodeSchema) });

  const onRequest = (values: MobileOtpRequestValues) => {
    send.mutate(values, { onSuccess: () => setMobile(values.mobile) });
  };

  const onVerify = (values: OtpCodeValues) => {
    if (!mobile) return;
    verify.mutate({ mobile, code: values.code }, { onSuccess: onDone });
  };

  if (mobile) {
    return (
      <form onSubmit={codeForm.handleSubmit(onVerify)} className="mt-4 flex flex-col gap-4">
        {verify.isError && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(verify.error)}</AlertDescription>
          </Alert>
        )}
        <p className="text-sm text-muted-foreground">Enter the code sent to {mobile}.</p>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="mobile-otp-code">OTP code</Label>
          <Input id="mobile-otp-code" inputMode="numeric" autoComplete="one-time-code" {...codeForm.register("code")} />
          {codeForm.formState.errors.code && (
            <p className="text-sm text-destructive">{codeForm.formState.errors.code.message}</p>
          )}
        </div>
        <Button type="submit" disabled={verify.isPending} className="mt-2">
          {verify.isPending ? "Verifying…" : "Verify & sign in"}
        </Button>
        <Button type="button" variant="ghost" onClick={() => setMobile(null)}>
          Use a different number
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={requestForm.handleSubmit(onRequest)} className="mt-4 flex flex-col gap-4">
      {send.isError && (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(send.error)}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="mobile">Mobile number</Label>
        <Input id="mobile" type="tel" autoComplete="tel" {...requestForm.register("mobile")} />
        {requestForm.formState.errors.mobile && (
          <p className="text-sm text-destructive">{requestForm.formState.errors.mobile.message}</p>
        )}
      </div>
      <Button type="submit" disabled={send.isPending} className="mt-2">
        {send.isPending ? "Sending…" : "Send OTP"}
      </Button>
    </form>
  );
}

function EmailOtpLogin({ onDone }: { onDone: () => void }) {
  const request = useEmailOtpRequest();
  const verify = useEmailOtpVerify();
  const mfaVerify = useMfaVerify();
  const [email, setEmail] = useState<string | null>(null);
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  const requestForm = useForm<EmailOtpRequestValues>({ resolver: zodResolver(emailOtpRequestSchema) });
  const codeForm = useForm<OtpCodeValues>({ resolver: zodResolver(otpCodeSchema) });
  const mfaForm = useForm<MfaCodeValues>({ resolver: zodResolver(mfaCodeSchema) });

  const onRequest = (values: EmailOtpRequestValues) => {
    request.mutate(values, { onSuccess: () => setEmail(values.email) });
  };

  const onVerify = (values: OtpCodeValues) => {
    if (!email) return;
    verify.mutate(
      { email, code: values.code },
      {
        onSuccess: (result) => {
          if (isMfaChallenge(result)) {
            setMfaToken(result.mfaToken);
          } else {
            onDone();
          }
        },
      }
    );
  };

  const onMfaSubmit = (values: MfaCodeValues) => {
    if (!mfaToken) return;
    mfaVerify.mutate({ mfa_token: mfaToken, code: values.code }, { onSuccess: onDone });
  };

  if (mfaToken) {
    return (
      <form onSubmit={mfaForm.handleSubmit(onMfaSubmit)} className="mt-4 flex flex-col gap-4">
        {mfaVerify.isError && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(mfaVerify.error)}</AlertDescription>
          </Alert>
        )}
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email-otp-mfa-code">Authenticator code</Label>
          <Input
            id="email-otp-mfa-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            {...mfaForm.register("code")}
          />
          {mfaForm.formState.errors.code && (
            <p className="text-sm text-destructive">{mfaForm.formState.errors.code.message}</p>
          )}
        </div>
        <Button type="submit" disabled={mfaVerify.isPending} className="mt-2">
          {mfaVerify.isPending ? "Verifying…" : "Verify"}
        </Button>
      </form>
    );
  }

  if (email) {
    return (
      <form onSubmit={codeForm.handleSubmit(onVerify)} className="mt-4 flex flex-col gap-4">
        {verify.isError && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(verify.error)}</AlertDescription>
          </Alert>
        )}
        <p className="text-sm text-muted-foreground">Enter the code sent to {email}.</p>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email-otp-code">OTP code</Label>
          <Input id="email-otp-code" inputMode="numeric" autoComplete="one-time-code" {...codeForm.register("code")} />
          {codeForm.formState.errors.code && (
            <p className="text-sm text-destructive">{codeForm.formState.errors.code.message}</p>
          )}
        </div>
        <Button type="submit" disabled={verify.isPending} className="mt-2">
          {verify.isPending ? "Verifying…" : "Verify & sign in"}
        </Button>
        <Button type="button" variant="ghost" onClick={() => setEmail(null)}>
          Use a different email
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={requestForm.handleSubmit(onRequest)} className="mt-4 flex flex-col gap-4">
      {request.isError && (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(request.error)}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="otp-email">Email</Label>
        <Input id="otp-email" type="email" autoComplete="email" {...requestForm.register("email")} />
        {requestForm.formState.errors.email && (
          <p className="text-sm text-destructive">{requestForm.formState.errors.email.message}</p>
        )}
      </div>
      <Button type="submit" disabled={request.isPending} className="mt-2">
        {request.isPending ? "Sending…" : "Send code"}
      </Button>
    </form>
  );
}
