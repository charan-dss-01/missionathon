import "./globals.css";
import { AuthProvider } from "@/components/AuthProvider";
import AppShell from "@/components/AppShell";

export const metadata = {
  title: "Operations Overview — PhishGuard Control Tower",
  description: "Cyber operations, agent health and explainable investigation decisions in PhishGuard Control Tower.",
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


