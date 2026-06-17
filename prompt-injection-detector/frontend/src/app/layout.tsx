import type { Metadata } from "next";
import "./globals.css";
import AppLayoutWrapper from "@/components/AppLayoutWrapper";

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
        <AppLayoutWrapper>{children}</AppLayoutWrapper>
      </body>
    </html>
  );
}
