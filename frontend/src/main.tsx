import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ThemeProvider } from "./context/ThemeContext";
import { WorkspaceProvider } from "./context/WorkspaceContext";
import { AppErrorBoundary } from "./components/ui/AppErrorBoundary";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1
    }
  }
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <WorkspaceProvider>
          <AppErrorBoundary>
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </AppErrorBoundary>
        </WorkspaceProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>
);
