"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import Script from "next/script";
import { registerUser, loginGoogleUser } from "@/lib/api";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();

  const handleGoogleCredential = useCallback(async (response: any) => {
    setLoading(true);
    setError(null);
    try {
      await loginGoogleUser(response.credential);
      router.push("/");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Google Registration failed.");
    } finally {
      setLoading(false);
    }
  }, [router]);

  const initializeGoogle = useCallback(() => {
    if (typeof window !== "undefined" && (window as any).google) {
      (window as any).google.accounts.id.initialize({
        client_id: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "1036329437199-dummyclientid.apps.googleusercontent.com",
        callback: handleGoogleCredential,
      });
      (window as any).google.accounts.id.renderButton(
        document.getElementById("google-signin-button"),
        { theme: "outline", size: "large", width: 360 }
      );
    }
  }, [handleGoogleCredential]);

  useEffect(() => {
    if (typeof window !== "undefined" && (window as any).google) {
      initializeGoogle();
    }
  }, [initializeGoogle]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim() || !confirmPassword.trim()) {
      setError("Please fill in all fields.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await registerUser(email, password);
      router.push("/");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Script
        src="https://accounts.google.com/gsi/client"
        strategy="afterInteractive"
        onLoad={initializeGoogle}
      />

      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">🛡️</div>
          <h2>Create Security Account</h2>
          <p>Register to monitor prompt injections and jailbreaks</p>
        </div>

        {error && (
          <div className="error-banner">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="auth-form-group">
            <label className="form-label" htmlFor="email">Email Address</label>
            <input
              id="email"
              type="email"
              className="input"
              placeholder="e.g. security@yourorg.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div className="auth-form-group">
            <label className="form-label" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              className="input"
              placeholder="Min. 6 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div className="auth-form-group">
            <label className="form-label" htmlFor="confirmPassword">Confirm Password</label>
            <input
              id="confirmPassword"
              type="password"
              className="input"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-full"
            style={{ marginTop: "1rem" }}
            disabled={loading}
          >
            {loading ? "🔄 Creating Account..." : "🛡️ Create Free Account"}
          </button>
        </form>

        {/* Separator */}
        <div style={{ display: "flex", alignItems: "center", margin: "1.5rem 0", gap: "0.5rem" }}>
          <div style={{ flex: 1, height: "1px", background: "rgba(255,255,255,0.06)" }} />
          <span style={{ color: "var(--text-dim)", fontSize: "0.75rem", textTransform: "uppercase" }}>or</span>
          <div style={{ flex: 1, height: "1px", background: "rgba(255,255,255,0.06)" }} />
        </div>

        {/* Google sign-in button container */}
        <div style={{ display: "flex", justifyContent: "center" }}>
          <div id="google-signin-button" style={{ width: "100%" }}></div>
        </div>

        <div className="auth-footer">
          Already have an account?
          <Link href="/login">Sign In instead</Link>
        </div>
      </div>
    </>
  );
}
