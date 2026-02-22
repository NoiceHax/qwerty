import "./globals.css";

export const metadata = {
  title: "qwerty - Enterprise Security Perimeter",
  description: "Next-Gen Vulnerability Intelligence. Identify, triage, and remediate threats before they reach production.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {children}
      </body>
    </html>
  );
}
