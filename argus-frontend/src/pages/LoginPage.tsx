import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, Shield, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

export function LoginPage() {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) {
      setError("API token is required");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { login } = await import("@/api/client");
      await login(token.trim());
      localStorage.setItem("argus_token", token.trim());
      navigate("/");
    } catch {
      setError("Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-md space-y-8 px-4">
        {/* Logo */}
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
            <Eye className="h-8 w-8 text-primary" />
          </div>
          <h1 className="mt-4 text-3xl font-bold tracking-tight text-primary">ARGUS</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Autonomous AI Red Team Platform
          </p>
          <p className="mt-1 text-xs text-muted-foreground/60">
            Continuous Security • 12 Attack Agents • Phase 1–5
          </p>
        </div>

        {/* Login form */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Lock className="h-4 w-4" />
              <span>Operator Authentication</span>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Input
                  type="password"
                  placeholder="Enter API token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  className="bg-background"
                />
                {error && (
                  <p className="mt-2 text-sm text-red-500">{error}</p>
                )}
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={loading}
              >
                <Shield className="mr-2 h-4 w-4" />
                {loading ? "Authenticating..." : "Access Platform"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground/40">
          ODINGARD SECURITY • SIX SENSE ENTERPRISE SERVICES
        </p>
      </div>
    </div>
  );
}
