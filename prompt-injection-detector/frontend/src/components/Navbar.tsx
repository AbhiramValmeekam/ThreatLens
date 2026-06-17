"use client";

import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";

const PAGE_TITLES: Record<string, string> = {
  "/": "Dashboard Overview",
  "/scanner": "Interactive Prompt Scanner",
  "/analytics": "Security Analytics & Insights",
  "/history": "Security Log History",
  "/batch": "Batch Scanner / Bulk Analysis",
};

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const title = PAGE_TITLES[pathname] || "ThreatLens Console";

  const handleLogout = () => {
    if (confirm("Are you sure you want to log out of ThreatLens?")) {
      localStorage.removeItem("token");
      router.push("/login");
    }
  };

  return (
    <header className="top-navbar">
      <div className="navbar-left">
        <span className="navbar-breadcrumb">Console</span>
        <span className="navbar-breadcrumb-separator">/</span>
        <span className="navbar-current-page">{title}</span>
      </div>

      <div className="navbar-right">
        {/* Status Indicators */}
        <div className="navbar-status-badge">
          <span className="status-dot green pulse" />
          <span className="status-text">API Online</span>
        </div>
        <div className="navbar-status-badge">
          <span className="status-dot green" />
          <span className="status-text">DB Connected</span>
        </div>

        {/* Latency Indicator */}
        <div className="navbar-latency">
          <span className="latency-label">API Latency:</span>
          <span className="latency-val font-mono">&lt; 15ms</span>
        </div>

        {/* Divider */}
        <div className="navbar-divider" />

        {/* Action Button */}
        {pathname !== "/scanner" && (
          <Link href="/scanner" className="btn btn-primary" style={{ padding: "0.4rem 0.9rem", fontSize: "0.8rem" }}>
            🛡️ Scan Prompt
          </Link>
        )}

        {/* Mock Profile Avatar (Click to Logout) */}
        <div
          className="user-profile"
          onClick={handleLogout}
          title="Sign Out of ThreatLens"
          style={{ cursor: "pointer" }}
        >
          <div className="avatar-gradient">AV</div>
        </div>
      </div>
    </header>
  );
}
