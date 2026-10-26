import { createTheme } from "@mui/material/styles";

const RADIUS = { sm: 12, md: 20, lg: 28, pill: 999 };
const SHADOW_SM = "0 2px 8px rgba(0, 0, 0, 0.04)";
const SHADOW_MD = "0 4px 16px rgba(0, 0, 0, 0.08)";
const SHADOW_LG = "0 8px 32px rgba(0, 0, 0, 0.12)";
const BRAND_RED = "#E53935";
const BRAND_BLUE = "#00d4ff";

const SEVERITY = {
  Critical: { bg: "rgba(220, 38, 38, 0.12)", fg: "#dc2626", border: "rgba(220, 38, 38, 0.25)" },
  High:     { bg: "rgba(234, 88, 12, 0.12)", fg: "#ea580c", border: "rgba(234, 88, 12, 0.25)" },
  Medium:   { bg: "rgba(217, 119, 6, 0.12)", fg: "#d97706", border: "rgba(217, 119, 6, 0.25)" },
  Low:      { bg: "rgba(14, 116, 144, 0.12)", fg: "#0e7490", border: "rgba(14, 116, 144, 0.25)" },
  Info:     { bg: "rgba(100, 116, 139, 0.12)", fg: "#64748b", border: "rgba(100, 116, 139, 0.25)" },
  Good:     { bg: "rgba(22, 163, 74, 0.12)", fg: "#16a34a", border: "rgba(22, 163, 74, 0.25)" },
  None:     { bg: "rgba(22, 163, 74, 0.12)", fg: "#16a34a", border: "rgba(22, 163, 74, 0.25)" },
};

export const baseTheme = {
  RADIUS,
  SHADOW_SM,
  SHADOW_MD,
  SHADOW_LG,
  BRAND_RED,
  BRAND_BLUE,
  SEVERITY,
  transitions: {
    fast: "250ms cubic-bezier(0.4, 0, 0.2, 1)",
    smooth: "400ms cubic-bezier(0.4, 0, 0.2, 1)",
  },
};

export const getSeverityStyles = (severity, mode = "light") => {
  const base = SEVERITY[severity] || SEVERITY.Info;
  const isDark = mode === "dark";
  return {
    bg: base.bg,
    fg: base.fg,
    border: base.border,
    chipBg: isDark
      ? severity === "Critical"
        ? "#581c1c"
        : severity === "High"
          ? "#5d3a0a"
          : severity === "Medium"
            ? "#5d3f0a"
            : severity === "Low"
              ? "#0a2d3a"
              : severity === "Info"
                ? "#1d2d3a"
                : "#1d3a24"
      : base.bg,
    chipFg: isDark ? "#FFFFFF" : base.fg,
  };
};

export const lightTheme = createTheme({
  palette: {
    mode: "light",
    background: { default: "#FAFAFB", paper: "#FFFFFF" },
    primary: { main: BRAND_RED, contrastText: "#FFFFFF" },
    secondary: { main: BRAND_BLUE, contrastText: "#000000" },
    error: { main: "#B71C1C" },
    success: { main: "#2E7D32" },
    warning: { main: "#FF8F00" },
    info: { main: "#0277BD" },
    text: { primary: "#1D1D1F", secondary: "#6E6E73", disabled: "#9E9E9E" },
    divider: "rgba(0, 0, 0, 0.08)",
  },
  typography: {
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
    h1: { fontSize: "64px", fontWeight: 800 },
    h2: { fontSize: "48px", fontWeight: 700 },
    h3: { fontSize: "28px", fontWeight: 700 },
    h4: { fontSize: "24px", fontWeight: 700 },
    h5: { fontSize: "20px", fontWeight: 700 },
    h6: { fontSize: "18px", fontWeight: 600 },
    body1: { fontSize: "16px", lineHeight: 1.6 },
    body2: { fontSize: "14px", lineHeight: 1.6 },
    button: { fontWeight: 600, textTransform: "none" },
  },
  shape: { borderRadius: RADIUS.md },
  shadows: [SHADOW_SM, SHADOW_MD, SHADOW_LG, "0 16px 48px rgba(0, 0, 0, 0.16)", ...Array(20).fill("none")],
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          background: "linear-gradient(180deg, #FAFAFB 0%, #FFFFFF 420px, #FFFFFF 100%)",
          color: "#1D1D1F",
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: "rgba(255, 255, 255, 0.72)",
          backdropFilter: "blur(20px) saturate(180%)",
          WebkitBackdropFilter: "blur(20px) saturate(180%)",
          borderBottom: "1px solid rgba(0, 0, 0, 0.08)",
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: RADIUS.pill,
          padding: "10px 24px",
          fontWeight: 600,
          transition: "250ms cubic-bezier(0.4, 0, 0.2, 1)",
        },
        containedPrimary: {
          boxShadow: "0 2px 8px rgba(229, 57, 53, 0.35)",
          "&:hover": {
            boxShadow: "0 4px 16px rgba(229, 57, 53, 0.45)",
            backgroundColor: "#F44336",
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          border: "1px solid rgba(0, 0, 0, 0.08)",
          borderRadius: RADIUS.lg,
          transition: "400ms cubic-bezier(0.4, 0, 0.2, 1)",
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 600, borderRadius: RADIUS.pill },
      },
    },
    MuiPaper: {
      styleOverrides: { root: { backgroundImage: "none" } },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 5, height: 10, backgroundColor: "#F5F5F7" },
        bar: { borderRadius: 5 },
      },
    },
    MuiAlert: {
      styleOverrides: { root: { borderRadius: RADIUS.sm } },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            backgroundColor: "#F5F5F7",
            borderRadius: RADIUS.sm,
            "&:hover fieldset": { borderColor: BRAND_RED },
            "&.Mui-focused fieldset": { borderColor: BRAND_RED },
          },
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        root: {
          "& .MuiSelect-select": {
            backgroundColor: "#F5F5F7",
            borderRadius: RADIUS.sm,
          },
        },
      },
    },
  },
});

export const darkTheme = createTheme({
  palette: {
    mode: "dark",
    background: { default: "#0A0A0B", paper: "#141415" },
    primary: { main: "#FF6F61", contrastText: "#000000" },
    secondary: { main: "#00d4ff", contrastText: "#000000" },
    error: { main: "#FF6F61" },
    success: { main: "#2E7D32" },
    warning: { main: "#FF8F00" },
    info: { main: "#00d4ff" },
    text: { primary: "#FFFFFF", secondary: "#A0A0A0", disabled: "#666666" },
    divider: "rgba(255, 255, 255, 0.08)",
  },
  typography: {
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
    h1: { fontSize: "64px", fontWeight: 800 },
    h2: { fontSize: "48px", fontWeight: 700 },
    h3: { fontSize: "28px", fontWeight: 700 },
    h4: { fontSize: "24px", fontWeight: 700 },
    h5: { fontSize: "20px", fontWeight: 700 },
    h6: { fontSize: "18px", fontWeight: 600 },
    body1: { fontSize: "16px", lineHeight: 1.6 },
    body2: { fontSize: "14px", lineHeight: 1.6 },
    button: { fontWeight: 600, textTransform: "none" },
  },
  shape: { borderRadius: RADIUS.md },
  shadows: [
    "none",
    "0 2px 8px rgba(0, 0, 0, 0.2)",
    "0 4px 16px rgba(0, 0, 0, 0.25)",
    "0 8px 32px rgba(0, 0, 0, 0.3)",
    "0 16px 48px rgba(0, 0, 0, 0.35)",
    ...Array(20).fill("none"),
  ],
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: { background: "#0A0A0B", color: "#FFFFFF" },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: "rgba(10, 10, 11, 0.72)",
          backdropFilter: "blur(20px) saturate(180%)",
          WebkitBackdropFilter: "blur(20px) saturate(180%)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: RADIUS.pill,
          padding: "10px 24px",
          fontWeight: 600,
          transition: "250ms cubic-bezier(0.4, 0, 0.2, 1)",
        },
        containedPrimary: {
          boxShadow: "0 2px 8px rgba(0, 212, 255, 0.35)",
          "&:hover": {
            boxShadow: "0 4px 16px rgba(0, 212, 255, 0.45)",
            backgroundColor: "#00b8e6",
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          border: "1px solid rgba(255, 255, 255, 0.08)",
          borderRadius: RADIUS.lg,
          transition: "400ms cubic-bezier(0.4, 0, 0.2, 1)",
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 600, borderRadius: RADIUS.pill },
      },
    },
    MuiPaper: {
      styleOverrides: { root: { backgroundImage: "none" } },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 5, height: 10, backgroundColor: "#2A2A2B" },
        bar: { borderRadius: 5 },
      },
    },
    MuiAlert: {
      styleOverrides: { root: { borderRadius: RADIUS.sm } },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            backgroundColor: "#1A1A1B",
            color: "#FFFFFF",
            borderRadius: RADIUS.sm,
            "&:hover fieldset": { borderColor: BRAND_BLUE },
            "&.Mui-focused fieldset": { borderColor: BRAND_BLUE },
          },
          "& .MuiInputLabel-root": { color: "#A0A0A0" },
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        root: {
          "& .MuiSelect-select": {
            backgroundColor: "#1A1A1B",
            color: "#FFFFFF",
            borderRadius: RADIUS.sm,
          },
        },
      },
    },
  },
});

const themeBundle = { lightTheme, darkTheme, getSeverityStyles, baseTheme };
export default themeBundle;