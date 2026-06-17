"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import Navbar from "@/components/Navbar";
import { getCurrentUser } from "@/lib/api";

export default function AppLayoutWrapper({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);

  const isAuthPage = pathname === "/login" || pathname === "/register";

  useEffect(() => {
    const checkAuth = async () => {
      if (isAuthPage) {
        setLoading(false);
        return;
      }

      const token = localStorage.getItem("token");
      if (!token) {
        router.push("/login");
        return;
      }

      try {
        await getCurrentUser();
        setAuthenticated(true);
      } catch (err) {
        console.error("Token verification failed:", err);
        // apiFetch will handle removal and redirect if 401, but fallback just in case:
        localStorage.removeItem("token");
        router.push("/login");
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, [pathname, isAuthPage, router]);

  // Loading state (only for protected routes)
  if (loading && !isAuthPage) {
    return (
      <div style={{
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--bg-primary)",
        color: "var(--text-secondary)",
        gap: "1rem"
      }}>
        <div className="brand-logo" style={{ fontSize: "4rem", marginBottom: "0.5rem" }}>🛡️</div>
        <div className="spinner" />
        <p style={{
          fontSize: "0.9rem",
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          fontWeight: 600
        }}>
          Establishing Secured Session...
        </p>
      </div>
    );
  }

  // Auth screen layout
  if (isAuthPage) {
    return <div className="auth-layout">{children}</div>;
  }

  // Dashboard layout (requires authentication)
  if (authenticated) {
    return (
      <div className="app-layout">
        <Sidebar />
        <div className="main-content">
          <Navbar />
          <div className="page-container">
            {children}
          </div>
        </div>
      </div>
    );
  }

  // Fallback (e.g. while redirecting)
  return null;
}
