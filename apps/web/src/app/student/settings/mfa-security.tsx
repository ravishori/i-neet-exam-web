"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import QRCode from "qrcode";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  SurfaceCard,
  SurfaceCardContent,
  SurfaceCardDescription,
  SurfaceCardHeader,
  SurfaceCardTitle,
} from "@/components/ds";
import { ApiError } from "@/lib/api-client";
import { useMe, useTotpConfirm, useTotpDisable, useTotpSetup } from "@/features/auth/use-auth";
import { mfaCodeSchema, type MfaCodeValues } from "@/features/auth/schemas";

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Something went wrong";
}

export function MfaSecurityCard() {
  const { data: me, isLoading } = useMe();
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const setup = useTotpSetup();
  const confirm = useTotpConfirm();
  const disable = useTotpDisable();

  const confirmForm = useForm<MfaCodeValues>({ resolver: zodResolver(mfaCodeSchema) });
  const disableForm = useForm<MfaCodeValues>({ resolver: zodResolver(mfaCodeSchema) });

  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!setup.data?.otpauth_url) {
      setQrDataUrl(null);
      return;
    }
    let cancelled = false;
    QRCode.toDataURL(setup.data.otpauth_url, { width: 220, margin: 1 })
      .then((url) => {
        if (!cancelled) setQrDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [setup.data?.otpauth_url]);

  const onBeginSetup = () => {
    setRecoveryCodes(null);
    setAcknowledged(false);
    confirmForm.reset();
    setup.mutate();
  };

  const onConfirm = (values: MfaCodeValues) => {
    confirm.mutate(values, {
      onSuccess: (result) => {
        setRecoveryCodes(result.recoveryCodes);
        confirmForm.reset();
        setup.reset();
      },
    });
  };

  const onDisable = (values: MfaCodeValues) => {
    disable.mutate(values, {
      onSuccess: () => {
        disableForm.reset();
        setRecoveryCodes(null);
      },
    });
  };

  if (isLoading) return null;

  const enabled = me?.totp_enabled === true;

  return (
    <SurfaceCard accent="none">
      <SurfaceCardHeader>
        <SurfaceCardTitle>Two-factor authentication</SurfaceCardTitle>
        <SurfaceCardDescription>
          {enabled
            ? "Enabled — an authenticator code is required at sign-in."
            : "Add an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.) for an extra layer of security."}
        </SurfaceCardDescription>
      </SurfaceCardHeader>
      <SurfaceCardContent className="flex flex-col gap-4">
        {/* Recovery codes are shown exactly once, immediately after enabling. */}
        {recoveryCodes && (
          <Alert>
            <AlertDescription>
              <p className="mb-2 font-medium">Save these recovery codes now — they will not be shown again.</p>
              <ul className="mb-3 grid grid-cols-2 gap-1 font-mono text-sm">
                {recoveryCodes.map((code) => (
                  <li key={code}>{code}</li>
                ))}
              </ul>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                I have saved these recovery codes somewhere safe.
              </label>
              {acknowledged && (
                <Button type="button" className="mt-3" onClick={() => setRecoveryCodes(null)}>
                  Done
                </Button>
              )}
            </AlertDescription>
          </Alert>
        )}

        {!enabled && !recoveryCodes && !setup.data && (
          <Button type="button" onClick={onBeginSetup} disabled={setup.isPending} className="w-fit">
            {setup.isPending ? "Starting…" : "Enable two-factor authentication"}
          </Button>
        )}

        {!enabled && setup.data && !recoveryCodes && (
          <form onSubmit={confirmForm.handleSubmit(onConfirm)} className="flex flex-col gap-4">
            {confirm.isError && (
              <Alert variant="destructive">
                <AlertDescription>{errorMessage(confirm.error)}</AlertDescription>
              </Alert>
            )}
            <p className="text-sm text-muted-foreground">
              Scan this QR code with your authenticator app, then enter the 6-digit code it shows.
            </p>
            {qrDataUrl ? (
              // eslint-disable-next-line @next/next/no-img-element -- client-generated data: URL, not a remote image
              <img src={qrDataUrl} alt="Authenticator QR code" width={220} height={220} className="rounded-lg border" />
            ) : (
              <p className="text-sm text-muted-foreground">Generating QR code…</p>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="totp-manual-secret">Can&apos;t scan? Enter this key manually</Label>
              <Input id="totp-manual-secret" readOnly value={setup.data.secret} onFocus={(e) => e.target.select()} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="totp-confirm-code">Authenticator code</Label>
              <Input
                id="totp-confirm-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                {...confirmForm.register("code")}
              />
              {confirmForm.formState.errors.code && (
                <p className="text-sm text-destructive">{confirmForm.formState.errors.code.message}</p>
              )}
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={confirm.isPending}>
                {confirm.isPending ? "Verifying…" : "Verify & enable"}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setup.reset()}>
                Cancel
              </Button>
            </div>
          </form>
        )}

        {enabled && !recoveryCodes && (
          <form onSubmit={disableForm.handleSubmit(onDisable)} className="flex flex-col gap-4">
            {disable.isError && (
              <Alert variant="destructive">
                <AlertDescription>{errorMessage(disable.error)}</AlertDescription>
              </Alert>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="totp-disable-code">
                Enter your authenticator code (or a recovery code) to disable two-factor authentication
              </Label>
              <Input id="totp-disable-code" autoComplete="one-time-code" {...disableForm.register("code")} />
              {disableForm.formState.errors.code && (
                <p className="text-sm text-destructive">{disableForm.formState.errors.code.message}</p>
              )}
            </div>
            <Button type="submit" variant="destructive" disabled={disable.isPending} className="w-fit">
              {disable.isPending ? "Disabling…" : "Disable two-factor authentication"}
            </Button>
            <p className="text-xs text-muted-foreground">
              To reconfigure with a new authenticator app, disable first, then enable again.
            </p>
          </form>
        )}
      </SurfaceCardContent>
    </SurfaceCard>
  );
}
