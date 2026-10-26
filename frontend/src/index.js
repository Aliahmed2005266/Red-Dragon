import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { ThemeProvider } from "@mui/material/styles";
import { CssBaseline } from "@mui/material";
import App from './App';
import ResultsWindow from './ResultsWindow';
import { lightTheme, darkTheme } from './theme';

// The desktop shell opens the results-only window with ?view=results&scanId=...;
// anything else gets the full application.
const params = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : new URLSearchParams();
const isResultsView = params.get('view') === 'results';

function Root() {
  const [themeMode, setThemeMode] = useState("light");

  useEffect(() => {
    const saved = localStorage.getItem("rd_theme");
    if (saved) setThemeMode(saved);
  }, []);

  useEffect(() => {
    localStorage.setItem("rd_theme", themeMode);
    document.documentElement.setAttribute("data-theme", themeMode);
  }, [themeMode]);

  const theme = themeMode === "dark" ? darkTheme : lightTheme;

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <React.StrictMode>
        {isResultsView ? <ResultsWindow themeMode={themeMode} /> : <App themeMode={themeMode} setThemeMode={setThemeMode} />}
      </React.StrictMode>
    </ThemeProvider>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Root />);