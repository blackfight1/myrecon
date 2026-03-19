import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";

// 路由代码分割 — 每个页面独立 chunk，首屏只加载 DashboardPage
const DashboardPage = lazy(() => import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const ProjectsPage = lazy(() => import("./pages/ProjectsPage").then((m) => ({ default: m.ProjectsPage })));
const QuickScanPage = lazy(() => import("./pages/QuickScanPage").then((m) => ({ default: m.QuickScanPage })));
const JobsPage = lazy(() => import("./pages/JobsPage").then((m) => ({ default: m.JobsPage })));
const JobLogsPage = lazy(() => import("./pages/JobLogsPage").then((m) => ({ default: m.JobLogsPage })));
const AssetsPage = lazy(() => import("./pages/AssetsPage").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage = lazy(() => import("./pages/AssetDetailPage").then((m) => ({ default: m.AssetDetailPage })));
const PortsPage = lazy(() => import("./pages/PortsPage").then((m) => ({ default: m.PortsPage })));
const FindingsPage = lazy(() => import("./pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const ScreenshotsPage = lazy(() => import("./pages/ScreenshotsPage").then((m) => ({ default: m.ScreenshotsPage })));
const MonitoringPage = lazy(() => import("./pages/MonitoringPage").then((m) => ({ default: m.MonitoringPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));

function PageLoading() {
  return (
    <div className="page-loading">
      <div className="page-loading-spinner" />
      <span>加载中…</span>
    </div>
  );
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { authenticated, loading } = useAuth();
  if (loading) return <PageLoading />;
  if (!authenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  const { authenticated, loading } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={
          loading ? (
            <PageLoading />
          ) : authenticated ? (
            <Navigate to="/" replace />
          ) : (
            <LoginPage />
          )
        }
      />
      <Route path="/" element={<RequireAuth><AppShell /></RequireAuth>}>
        <Route index element={<Suspense fallback={<PageLoading />}><DashboardPage /></Suspense>} />
        <Route path="projects" element={<Suspense fallback={<PageLoading />}><ProjectsPage /></Suspense>} />
        <Route path="quick-scan" element={<Suspense fallback={<PageLoading />}><QuickScanPage /></Suspense>} />
        <Route path="jobs" element={<Suspense fallback={<PageLoading />}><JobsPage /></Suspense>} />
        <Route path="jobs/:jobId/logs" element={<Suspense fallback={<PageLoading />}><JobLogsPage /></Suspense>} />
        <Route path="assets" element={<Suspense fallback={<PageLoading />}><AssetsPage /></Suspense>} />
        <Route path="assets/:id" element={<Suspense fallback={<PageLoading />}><AssetDetailPage /></Suspense>} />
        <Route path="ports" element={<Suspense fallback={<PageLoading />}><PortsPage /></Suspense>} />
        <Route path="findings" element={<Suspense fallback={<PageLoading />}><FindingsPage /></Suspense>} />
        <Route path="screenshots" element={<Suspense fallback={<PageLoading />}><ScreenshotsPage /></Suspense>} />
        <Route path="monitoring" element={<Suspense fallback={<PageLoading />}><MonitoringPage /></Suspense>} />
        <Route path="settings" element={<Suspense fallback={<PageLoading />}><SettingsPage /></Suspense>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
