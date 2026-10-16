import "./globals.css";
import { AuthProvider } from "@/components/AuthProvider";
import AppShell from "@/components/AppShell";

export const metadata = {
  title: "PhishGuard AI — Autonomous Cyber Threat Defense",
  description: "Agentic cyber threat intelligence and deterministic security pipeline.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <AppShell>{children}</AppShell>
        </AuthProvider>
      </body>
    </html>
  );
}


