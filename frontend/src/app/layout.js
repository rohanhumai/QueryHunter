import "./globals.css";

export const metadata = {
  title: "QueryHunter AI",
  description: "Natural Language Security Log Analyzer",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
