"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  PageHeader,
  StudentPage,
  SurfaceCard,
  SurfaceCardContent,
  SurfaceCardDescription,
  SurfaceCardHeader,
  SurfaceCardTitle,
} from "@/components/ds";
import { ApiError } from "@/lib/api-client";
import { usersApi } from "@/features/users/api";
import { MfaSecurityCard } from "./mfa-security";

const LANGUAGES = [
  { code: "en", label: "English" },
  { code: "hi", label: "हिन्दी (Hindi)" },
];

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data: profile, isLoading } = useQuery({ queryKey: ["users", "me"], queryFn: usersApi.me });

  const updateLanguage = useMutation({
    mutationFn: (preferred_language: string) => usersApi.updateMe({ preferred_language }),
    onSuccess: (updated) => queryClient.setQueryData(["users", "me"], updated),
  });

  return (
    <StudentPage width="md">
      <PageHeader
        eyebrow="Account"
        title="Settings"
        description="Content language and study preferences. Theme is available from the header."
      />

      {isLoading ? (
        <Skeleton className="h-40 w-full rounded-2xl" aria-busy="true" />
      ) : (
        <SurfaceCard accent="none">
          <SurfaceCardHeader>
            <SurfaceCardTitle>Preferences</SurfaceCardTitle>
            <SurfaceCardDescription>Changes save as soon as you pick a language.</SurfaceCardDescription>
          </SurfaceCardHeader>
          <SurfaceCardContent className="flex flex-col gap-4">
            {updateLanguage.isError && (
              <Alert variant="destructive">
                <AlertDescription>
                  {updateLanguage.error instanceof ApiError
                    ? updateLanguage.error.message
                    : "We couldn’t save that setting. Try again."}
                </AlertDescription>
              </Alert>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="content-language">Content language</Label>
              <select
                id="content-language"
                className="h-11 w-full max-w-xs rounded-lg border bg-background px-3 text-sm"
                value={profile?.preferred_language ?? "en"}
                disabled={updateLanguage.isPending}
                onChange={(e) => updateLanguage.mutate(e.target.value)}
              >
                {LANGUAGES.map((l) => (
                  <option key={l.code} value={l.code}>
                    {l.label}
                  </option>
                ))}
              </select>
              <p className="text-caption">
                Concept notes and questions show in this language where translated, with English as a fallback.
              </p>
            </div>
          </SurfaceCardContent>
        </SurfaceCard>
      )}

      <MfaSecurityCard />
    </StudentPage>
  );
}
