"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import Script from "next/script";
import { loginUser, loginGoogleUser } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
      setError(err instanceof Error ? err.message : "Google Authentication failed.");
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
    if (!email.trim() || !password.trim()) {
      setError("Please fill in all fields.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await loginUser(email, password);
      router.push("/");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Invalid credentials.");
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
          <h2>Sign In to ThreatLens</h2>
          <p>Enter your credentials to access the security console</p>
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
              placeholder="e.g. admin@threatlens.com"
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
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
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
            {loading ? "🔄 Authenticating..." : "🔍 Sign In to Dashboard"}
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
          New to ThreatLens?
          <Link href="/register">Create an account</Link>
        </div>
      </div>
    </>
  );
}
