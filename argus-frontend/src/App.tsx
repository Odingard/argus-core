import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "./components/layout/AppLayout";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LiveScanPage } from "./pages/LiveScanPage";
import { PendingScanPage } from "./pages/PendingScanPage";
import { CompletedScanPage } from "./pages/CompletedScanPage";
import { MCPServersPage } from "./pages/MCPServersPage";
import { AIAgentsPage } from "./pages/AIAgentsPage";
import { PipelinesPage } from "./pages/PipelinesPage";
import { MemoryStoresPage } from "./pages/MemoryStoresPage";
import { FindingsPage } from "./pages/FindingsPage";
import { CompoundChainsPage } from "./pages/CompoundChainsPage";
import { OWASPMappingPage } from "./pages/OWASPMappingPage";
import { CorpusPage } from "./pages/CorpusPage";
import { GauntletPage } from "./pages/GauntletPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { SettingsPage } from "./pages/SettingsPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("argus_token");
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<DashboardPage />} />
          {/* Activity */}
          <Route path="scan/live" element={<LiveScanPage />} />
          <Route path="scan/pending" element={<PendingScanPage />} />
          <Route path="scan/completed" element={<CompletedScanPage />} />
          <Route path="scan/:scanId" element={<ScanDetailPage />} />
          {/* Targets */}
          <Route path="targets/mcp-servers" element={<MCPServersPage />} />
          <Route path="targets/ai-agents" element={<AIAgentsPage />} />
          <Route path="targets/pipelines" element={<PipelinesPage />} />
          <Route path="targets/memory-stores" element={<MemoryStoresPage />} />
          {/* Findings */}
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/chains" element={<CompoundChainsPage />} />
          <Route path="findings/owasp" element={<OWASPMappingPage />} />
          {/* Platform */}
          <Route path="platform/corpus" element={<CorpusPage />} />
          <Route path="platform/gauntlet" element={<GauntletPage />} />
          <Route path="platform/monitoring" element={<MonitoringPage />} />
          <Route path="platform/settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
