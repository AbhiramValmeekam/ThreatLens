"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard Home", icon: "🏠" },
  { href: "/scanner", label: "Prompt Scanner", icon: "🛡️" },
  { href: "/analytics", label: "Analytics", icon: "📊" },
  { href: "/history", label: "Scan History", icon: "📋" },
  { href: "/batch", label: "Batch Scanner", icon: "📂" },
];

export default function Navbar() {
  const pathname = usePathname();

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        {NAV_ITEMS.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`nav-link ${pathname === item.href ? "active" : ""}`}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
