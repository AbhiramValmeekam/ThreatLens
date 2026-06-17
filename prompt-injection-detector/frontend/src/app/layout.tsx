import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "ThreatLens — LLM Security Monitor",
  description:
    "AI-powered security platform that detects Prompt Injection, Jailbreak, System Prompt Extraction, Data Exfiltration, Role Hijacking, Indirect Prompt Injection, and Tool Abuse attacks before they reach an LLM.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="app-layout">
          <Sidebar />
          <div className="main-content">
            <Navbar />
            <div className="page-container">
              {children}
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
