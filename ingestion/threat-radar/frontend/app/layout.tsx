import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatRadar",
  description: "Candidate collection radar for posts, images, and links.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}


// test 10