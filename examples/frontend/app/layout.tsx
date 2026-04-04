export const metadata = {
  title: "NATS Chat — Demo",
  description: "Minimal demo: Keycloak OIDC → NATS JWT Auth → NATS WebSocket",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: "2rem" }}>
        {children}
      </body>
    </html>
  );
}
