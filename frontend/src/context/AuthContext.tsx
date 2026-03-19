import {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
    type ReactNode,
} from "react";
import { getToken, setToken, clearToken, apiPost } from "../api/client";

interface AuthState {
    authenticated: boolean;
    username: string;
    loading: boolean;
}

interface AuthContextValue extends AuthState {
    login: (username: string, password: string) => Promise<void>;
    logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error("useAuth must be used within AuthProvider");
    return ctx;
}

interface LoginResponse {
    token: string;
    expiresAt: string;
    username: string;
}

export function AuthProvider({ children }: { children: ReactNode }) {
    const [state, setState] = useState<AuthState>({
        authenticated: false,
        username: "",
        loading: true,
    });

    // On mount, check if we have a valid token
    useEffect(() => {
        const token = getToken();
        if (!token) {
            setState({ authenticated: false, username: "", loading: false });
            return;
        }
        // Validate token by calling /api/auth/check
        fetch("/api/auth/check", {
            headers: { Authorization: `Bearer ${token}` },
        })
            .then((res) => {
                if (res.ok) return res.json();
                throw new Error("unauthorized");
            })
            .then((data: { authenticated: boolean; username: string }) => {
                setState({
                    authenticated: true,
                    username: data.username || "",
                    loading: false,
                });
            })
            .catch(() => {
                clearToken();
                setState({ authenticated: false, username: "", loading: false });
            });
    }, []);

    const login = useCallback(async (username: string, password: string) => {
        const resp = await apiPost<
            { username: string; password: string },
            LoginResponse
        >("/auth/login", { username, password });
        setToken(resp.token);
        setState({
            authenticated: true,
            username: resp.username,
            loading: false,
        });
    }, []);

    const logout = useCallback(() => {
        clearToken();
        setState({ authenticated: false, username: "", loading: false });
    }, []);

    return (
        <AuthContext.Provider value={{ ...state, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
}
