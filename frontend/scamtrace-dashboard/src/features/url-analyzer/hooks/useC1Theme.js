import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const STORAGE_KEY = 'c1.theme';

function readInitialTheme() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') {
      return saved;
    }
    // Respect OS preference on first visit
    if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      return 'light';
    }
    return 'dark'; // Default to SOC dark theme
  } catch {
    return 'dark';
  }
}

export function useC1Theme() {
  const [theme, setThemeState] = useState(readInitialTheme);

  const setTheme = useCallback((newTheme) => {
    setThemeState((prev) => {
      const resolved = typeof newTheme === 'function' ? newTheme(prev) : newTheme;
      try {
        localStorage.setItem(STORAGE_KEY, resolved);
      } catch {
        // Private browsing fallback
      }
      return resolved;
    });
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  }, [setTheme]);

  // Sync with document root so global elements (nav, shell, modals) adapt seamlessly
  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-c1-theme', theme);
      if (theme === 'dark') {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    }
  }, [theme]);

  // Sync with OS preference changes if user hasn't explicitly set a preference
  useEffect(() => {
    try {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
      const handleChange = (e) => {
        if (!localStorage.getItem(STORAGE_KEY)) {
          setThemeState(e.matches ? 'light' : 'dark');
        }
      };
      mediaQuery.addEventListener?.('change', handleChange);
      return () => mediaQuery.removeEventListener?.('change', handleChange);
    } catch {
      return undefined;
    }
  }, []);

  return { theme, setTheme, toggleTheme, isDark: theme === 'dark' };
}

export const C1ThemeContext = createContext({
  theme: 'dark',
  isDark: true,
  setTheme: () => {},
  toggleTheme: () => {},
});

export function C1ThemeProvider({ children }) {
  const themeState = useC1Theme();
  return React.createElement(C1ThemeContext.Provider, { value: themeState }, children);
}

export function useC1ThemeContext() {
  return useContext(C1ThemeContext);
}

