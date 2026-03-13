import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type ThemeName = "blue" | "green" | "purple" | "orange";

const THEMES: { id: ThemeName; label: string }[] = [
    { id: "blue", label: "Blue" },
    { id: "green", label: "Green" },
    { id: "purple", label: "Purple" },
    { id: "orange", label: "Orange" }
];

const STORAGE_KEY = "myrecon.theme";

interface ThemeState {
    theme: ThemeName;
    themes: typeof THEMES;
    setTheme: (t: ThemeName) => void;
}

const ThemeContext = createContext<ThemeState | null>(null);

function loadTheme(): ThemeName {
    if (typeof window === "undefined") return "blue";
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved && THEMES.some((t) => t.id === saved)) return saved as ThemeName;
    return "blue";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [theme, setThemeState] = useState<ThemeName>(() => loadTheme());

    const setTheme = (t: ThemeName) => {
        setThemeState(t);
        window.localStorage.setItem(STORAGE_KEY, t);
    };

    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
    }, [theme]);

    return (
        <ThemeContext.Provider value={{ theme, themes: THEMES, setTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}

export function useTheme(): ThemeState {
    const ctx = useContext(ThemeContext);
    if (!ctx) throw new Error("useTheme must be used inside ThemeProvider");
    return ctx;
}
