import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { AssetsPage } from "./pages/AssetsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingsPage } from "./pages/FindingsPage";
import { JobsPage } from "./pages/JobsPage";
import { JobLogsPage } from "./pages/JobLogsPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { PortsPage } from "./pages/PortsPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { QuickScanPage } from "./pages/QuickScanPage";
import { ScreenshotsPage } from "./pages/ScreenshotsPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<AppShell />}>
        <Route index element={<DashboardPage />} />
        <Route path="projects" element={<ProjectsPage />} />
        <Route path="quick-scan" element={<QuickScanPage />} />
        <Route path="jobs" element={<JobsPage />} />
        <Route path="jobs/:jobId/logs" element={<JobLogsPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="assets/:id" element={<AssetDetailPage />} />
        <Route path="ports" element={<PortsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="screenshots" element={<ScreenshotsPage />} />
        <Route path="monitoring" element={<MonitoringPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
