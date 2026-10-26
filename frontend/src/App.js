import React, { useState, useEffect, useCallback } from "react";
import {
  Typography,
  TextField,
  Button,
  Box,
  Paper,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  AppBar,
  Toolbar,
  Select,
  MenuItem,
  FormControl,
  FormControlLabel,
  Checkbox,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Snackbar,
} from "@mui/material";
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Download as DownloadIcon,
  Send as SendIcon,
  ExpandLess as ExpandLessIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Extension as PluginIcon,
  Cloud as CloudIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  Http as HttpIcon,
  Chat as ChatIcon,
  AutoAwesome as AIIcon,
  Delete as DeleteIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckIcon,
  RadioButtonUnchecked as UncheckedIcon,
  OpenInNew as OpenInNewIcon,
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
} from "@mui/icons-material";
import axios from "axios";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from "recharts";
import "./App.css";

// Unified severity palette shared by the donut chart, severity chips, the
// risk score and the statistics cards, so a given severity is always the same
// colour everywhere in the app (Critical -> Info).
export const COLORS = ["#dc2626", "#ea580c", "#d97706", "#0e7490", "#64748b"];
// Select sentinel for the "Custom model..." option in the model dropdowns.
// Lets the user type any model name their provider accepts, not only the
// presets the backend suggests.
const CUSTOM_MODEL_OPTION = "__custom__";
// The desktop backend issues a per-launch secret and requires it on every API
// call, so a web page the user happens to visit cannot drive this machine into
// scanning a target of its choosing. The backend injects the token into the
// page it serves; under `npm start` there is no token and the guard is off,
// which is the development path.
const BOOTSTRAP =
  (typeof window !== "undefined" && window.__RED_DRAGON__) || {};
const API_TOKEN = BOOTSTRAP.token || "";
export const IS_DESKTOP = Boolean(
  window.redDragon && window.redDragon.isDesktop
);

if (API_TOKEN) {
  axios.defaults.headers.common["X-RD-Token"] = API_TOKEN;
}

const SCAN_MODULES = [
  { id: "all", name: "Full Scan", description: "Run all scanners" },
  { id: "web", name: "Web Vulnerabilities", description: "SQLi, XSS, IDOR, LFI, etc." },
  { id: "sqli", name: "SQL Injection", description: "Test for SQL injection" },
  { id: "xss", name: "XSS", description: "Cross-site scripting tests" },
  { id: "idor", name: "IDOR", description: "Insecure direct object reference" },
  { id: "lfi", name: "LFI/RFI", description: "Local/Remote file inclusion" },
  { id: "cmd", name: "Command Injection", description: "OS command injection" },
  { id: "upload", name: "File Upload", description: "Malicious file upload tests" },
  { id: "graphql", name: "GraphQL", description: "GraphQL introspection & attacks" },
  { id: "api", name: "API Security", description: "REST/GraphQL API security" },
  { id: "cloud", name: "Cloud Security", description: "AWS/GCP/Azure misconfigurations" },
  { id: "cve", name: "CVE Detection", description: "Known vulnerability matching" },
  { id: "wordpress", name: "WordPress", description: "WP plugin/theme scanning" },
  { id: "redirect", name: "Open Redirect", description: "Open redirect vulnerabilities" },
  { id: "ai", name: "AI/LLM Security", description: "OWASP Top 10 for LLM" },
  { id: "ports", name: "Port Scanner", description: "Open port scanning" },
  { id: "firewall", name: "Firewall/WAF", description: "WAF detection & bypass" },
  { id: "rate", name: "Rate Limiting", description: "Rate limit effectiveness" },
  { id: "network", name: "Network", description: "Ports + Firewall + Rate" },
  { id: "fuzz", name: "Fuzzer", description: "Input fuzzing & discovery" },
  { id: "subdomain", name: "Subdomains", description: "Subdomain enumeration" },
  { id: "sitemap", name: "Site Mapping", description: "Map site structure" },
  { id: "ssrf", name: "SSRF", description: "Server-Side Request Forgery" },
  { id: "xxe", name: "XXE Injection", description: "XML External Entity injection" },
  { id: "ssti", name: "SSTI", description: "Server-Side Template Injection" },
  { id: "deser", name: "Deserialization", description: "Insecure deserialization attacks" },
  { id: "params", name: "Parameter Discovery", description: "Find URL parameters & confirm which are live" },
  { id: "fingerprint", name: "Tech Fingerprint", description: "Detect server, languages, databases & frameworks" },
];

// Architecture categories and how they are presented in the UI
const ARCH_SECTIONS = [
  { key: "servers", label: "Web Server", icon: "server" },
  { key: "languages", label: "Programming Languages", icon: "language" },
  { key: "databases", label: "Databases", icon: "database" },
  { key: "cms", label: "CMS", icon: "cms" },
  { key: "frameworks", label: "Frameworks", icon: "framework" },
  { key: "frontend", label: "Frontend Libraries", icon: "frontend" },
  { key: "apis", label: "APIs", icon: "api" },
  { key: "infrastructure", label: "CDN / WAF / Proxy", icon: "infra" },
];

const CONFIDENCE_COLOR = {
  high: { bg: "#DCFCE7", fg: "#166534", label: "High" },
  medium: { bg: "#FEF3C7", fg: "#92400E", label: "Medium" },
  low: { bg: "#F5F5F7", fg: "#6E6E73", label: "Low" },
};

function TabPanel({ children, value, index, ...other }) {
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// Shared cell styles for the Brute Force results table
const bfThStyle = {
  padding: "8px 12px",
  textAlign: "left",
  fontWeight: "bold",
  color: "#1D1D1F",
  borderBottom: "2px solid rgba(0, 0, 0, 0.08)",
  whiteSpace: "nowrap",
};
const bfTdStyle = {
  padding: "8px 12px",
  color: "#1D1D1F",
  borderBottom: "1px solid rgba(0, 0, 0, 0.05)",
  whiteSpace: "nowrap",
};

// Vulnerability tests available in the Fuzz & Test chain
const FUZZ_VULN_TESTS = [
  { id: "sqli", label: "SQL Injection" },
  { id: "xss", label: "XSS" },
  { id: "lfi", label: "LFI / File Inclusion" },
  { id: "redirect", label: "Open Redirect" },
];

// Shared severity -> colour mapping (used by the main app and the
// results-only window).
export const getSeverityColor = (severity) => {
  switch (severity) {
    case "Critical":
      return "#dc2626";
    case "High":
      return "#ea580c";
    case "Medium":
      return "#d97706";
    case "Low":
      return "#0e7490";
    case "Info":
      return "#64748b";
    case "Good":
      return "#16a34a";
    case "None":
      return "#16a34a";
    default:
      return "#64748b";
  }
};

// Shared finding-type -> icon mapping (used by the main app and the
// results-only window).
export const getTypeIcon = (type) => {
  switch (type) {
    case "SQL Injection":
      return <BugIcon />;
    case "Cross-Site Scripting (XSS)":
      return <BugIcon />;
    case "Insecure Direct Object Reference (IDOR)":
      return <SecurityIcon />;
    case "Local File Inclusion (LFI)":
      return <CodeIcon />;
    case "Unrestricted File Upload":
      return <PluginIcon />;
    case "Command Injection":
      return <CodeIcon />;
    case "GraphQL":
      return <CodeIcon />;
    case "API Security":
      return <CodeIcon />;
    case "Cloud Security":
      return <CloudIcon />;
    case "WordPress":
      return <PluginIcon />;
    default:
      return <SecurityIcon />;
  }
};

// Small copy-to-clipboard button used next to URLs, payloads and other
// one-off values in the findings list. Shows "Copied" for two seconds.
export function CopyButton({ text, label = "Copy", size = "small" }) {
  const [copied, setCopied] = useState(false);
  if (!text) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      // Clipboard unavailable (or blocked); the text is still selectable
    }
  };

  return (
    <Button
      size={size}
      onClick={copy}
      startIcon={<CodeIcon sx={{ fontSize: 14 }} />}
      sx={{ color: "#00d4ff", fontSize: 11, ml: 1, py: 0 }}
    >
      {copied ? "Copied" : label}
    </Button>
  );
}

// Renders a finding's proof-of-concept: where it was found, the request that
// was sent, and the response that demonstrated the vulnerability.
export function PocBlock({ poc }) {
  const [copied, setCopied] = useState(false);
  if (!poc) return null;

  const loc = poc.location || {};

  const copyCurl = async () => {
    const curl = poc.request?.curl;
    if (!curl) return;
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      // Clipboard unavailable (or blocked); the text is still selectable
    }
  };

  const labelStyle = { color: "#00d4ff", fontWeight: "bold" };
  const codeStyle = {
    color: "#00ff00",
    backgroundColor: "#1e1e1e",
    padding: "2px 6px",
    borderRadius: "4px",
    wordBreak: "break-all",
  };
  const preStyle = {
    m: 0,
    p: 1.5,
    bgcolor: "#111",
    borderRadius: 1,
    fontSize: 11,
    fontFamily: "Consolas, Monaco, monospace",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    maxHeight: 220,
    overflow: "auto",
  };

  return (
    <Box
      sx={{
        mt: 2,
        p: 2,
        borderRadius: 2,
        border: "1px solid rgba(255,193,7,0.35)",
        bgcolor: "rgba(255,193,7,0.05)",
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
        <BugIcon sx={{ color: "#ffc107", fontSize: 18 }} />
        <Typography variant="subtitle2" sx={{ color: "#ffc107", fontWeight: "bold" }}>
          Proof of Concept
        </Typography>
        {poc.marker?.type === "reflected-payload" && (
          <Chip size="small" label="payload reflected" sx={{ bgcolor: "#ffc107", color: "#000", fontWeight: "bold" }} />
        )}
        {poc.match && (
          <Chip size="small" label={`matched by ${poc.match}`} sx={{ bgcolor: "#37474f", color: "#cfd8dc" }} />
        )}
      </Box>

      {/* Exactly where it was found */}
      <Typography variant="body2" sx={{ color: "#b0b0b0", mb: 1 }}>
        <span style={labelStyle}>Where:</span>{" "}
        <code style={codeStyle}>{loc.method || "GET"}</code>{" "}
        <code style={codeStyle}>{loc.endpoint || loc.url || "N/A"}</code>
        {loc.parameter && (
          <>
            {" "}
            <span style={labelStyle}>parameter:</span>{" "}
            <code style={{ ...codeStyle, color: "#ff6b6b" }}>{loc.parameter}</code>
          </>
        )}
      </Typography>

      {!poc.available ? (
        <Typography variant="caption" sx={{ color: "#888", fontStyle: "italic" }}>
          {poc.reason || "No HTTP evidence was captured for this finding."}
        </Typography>
      ) : (
        <>
          {/* The exact request that was sent */}
          {poc.request?.curl && (
            <Box sx={{ mb: 1.5 }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                <Typography variant="caption" sx={{ ...labelStyle, display: "block" }}>
                  Request
                </Typography>
                <Button size="small" onClick={copyCurl} startIcon={<CodeIcon sx={{ fontSize: 14 }} />} sx={{ color: "#00d4ff", fontSize: 11 }}>
                  {copied ? "Copied" : "Copy"}
                </Button>
              </Box>
              <Box component="pre" sx={{ ...preStyle, color: "#d4d4d4", border: "1px solid #333" }}>
                {poc.request.curl}
              </Box>
            </Box>
          )}

          {poc.request?.headers && Object.keys(poc.request.headers).length > 0 && (
            <Typography variant="caption" sx={{ display: "block", color: "#78909c", mb: 1, wordBreak: "break-all" }}>
              {Object.entries(poc.request.headers).map(([k, v]) => `${k}: ${v}`).join("   |   ")}
            </Typography>
          )}

          {/* The response that showed the vulnerability */}
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" sx={{ ...labelStyle, display: "block", mb: 0.5 }}>
              Response {poc.response?.status} ({poc.response?.body_length} bytes)
            </Typography>
            {poc.response?.excerpt && (
              <Box component="pre" sx={{ ...preStyle, color: "#ffe082", border: "1px solid #ffc107" }}>
                {poc.response.excerpt}
              </Box>
            )}
          </Box>

          {/* What exactly proved it */}
          {poc.marker?.value && (
            <Box sx={{ mb: 1 }}>
              <Typography variant="caption" sx={{ ...labelStyle, display: "block" }}>
                Marker ({poc.marker.type}
                {poc.marker.offset != null ? ` at byte ${poc.marker.offset}` : ""})
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0, p: 1, mt: 0.5,
                  bgcolor: "#1e1e1e", color: "#ff6b6b",
                  border: "1px solid #4a2020", borderRadius: 1,
                  fontSize: 11, fontFamily: "Consolas, Monaco, monospace",
                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                }}
              >
                {poc.marker.value}
              </Box>
              {poc.marker.description && (
                <Typography variant="caption" sx={{ color: "#888", fontStyle: "italic", display: "block", mt: 0.5 }}>
                  {poc.marker.description}
                </Typography>
              )}
            </Box>
          )}

          {/* Comparison against the clean request */}
          {poc.baseline && (
            <Typography variant="caption" sx={{ color: "#78909c", display: "block" }}>
              Baseline (no payload): {poc.baseline.status}, {poc.baseline.body_length} bytes
            </Typography>
          )}
        </>
      )}
    </Box>
  );
}

function App({ themeMode = "light", setThemeMode }) {
  const [targetUrl, setTargetUrl] = useState("");
  // Toast notification state
  const [snackbar, setSnackbar] = useState({
    open: false,
    severity: "info",
    message: "",
  });

  const showToast = useCallback((message, severity = "info") => {
    setSnackbar({ open: true, severity, message });
    setTimeout(() => setSnackbar((prev) => ({ ...prev, open: false })), 4000);
  }, []);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState("idle");
  const [activeScans, setActiveScans] = useState({});
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [selectedTab, setSelectedTab] = useState(0);
  const [expandedFindings, setExpandedFindings] = useState({});
  const [selectedModules, setSelectedModules] = useState(["all"]);
  const [scanMode, setScanMode] = useState("url");
  // One-click "run all scans" state
  const [allScansRunning, setAllScansRunning] = useState(false);
  const [allScanProgress, setAllScanProgress] = useState({});
  
  // AI Chat state
  const [aiDialogOpen, setAiDialogOpen] = useState(false);
  const [aiProviders, setAiProviders] = useState([]);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  // True while the user is typing a model name that is not in the preset list
  // (they chose "Custom model..." in the dropdown).
  const [isCustomModel, setIsCustomModel] = useState(false);
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiMessages, setAiMessages] = useState([]);
  const [aiInput, setAiInput] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  // Only the setter is used (to keep the AI dialog's busy state in sync);
  // the value itself is tracked by aiLoading/agentBusy elsewhere.
  const [, setAiAnalyzing] = useState(false);

  // Scan module selection modal
  const [modulesDialogOpen, setModulesDialogOpen] = useState(false);

  // Attack Tools: Intruder state
  const [toolsTab, setToolsTab] = useState(0);
  // Source Analyzer state
  const [saUrl, setSaUrl] = useState("");
  const [saLoading, setSaLoading] = useState(false);
  const [saError, setSaError] = useState("");
  const [saResult, setSaResult] = useState(null);
  const [saShowSource, setSaShowSource] = useState(false);
  // Parameter Discovery state
  const [pdTarget, setPdTarget] = useState("");
  const [pdLoading, setPdLoading] = useState(false);
  const [pdError, setPdError] = useState("");
  const [pdResult, setPdResult] = useState(null);
  // Technology fingerprint state
  const [tfTarget, setTfTarget] = useState("");
  const [tfLoading, setTfLoading] = useState(false);
  const [tfError, setTfError] = useState("");
  const [tfResult, setTfResult] = useState(null);
  // AI Security Agent state
  const [agentSession, setAgentSession] = useState(null);
  const [agentKey, setAgentKey] = useState("");
  const [agentStatus, setAgentStatus] = useState("");
  const [agentError, setAgentError] = useState("");
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentMode, setAgentMode] = useState("ask");
  const [agentAudience, setAgentAudience] = useState("technical");
  const [agentQuestion, setAgentQuestion] = useState("");
  const [agentMessages, setAgentMessages] = useState([]);
  const [agentReport, setAgentReport] = useState("");
  const [agentAuthorised, setAgentAuthorised] = useState(false);
  const [agentScope, setAgentScope] = useState("");
  const [intruderTarget, setIntruderTarget] = useState("");
  const [intruderAttackType, setIntruderAttackType] = useState("sniper");
  const [intruderMethod, setIntruderMethod] = useState("GET");
  const [intruderParams, setIntruderParams] = useState("id");
  const [intruderParamPos, setIntruderParamPos] = useState("query");
  const [payloadSet1, setPayloadSet1] = useState("1\n2\n3");
  const [payloadSet2, setPayloadSet2] = useState("");
  const [intruderHeaders, setIntruderHeaders] = useState("");
  const [intruderBody, setIntruderBody] = useState("");
  const [matchType, setMatchType] = useState("contains");
  const [matchValue, setMatchValue] = useState("");
  const [intruderRunning, setIntruderRunning] = useState(false);
  const [intruderAttackId, setIntruderAttackId] = useState(null);
  const [intruderResults, setIntruderResults] = useState([]);
  const [intruderStatus, setIntruderStatus] = useState(null);
  const [intruderError, setIntruderError] = useState("");

  // Attack Tools: Repeater state
  const [repMethod, setRepMethod] = useState("GET");
  const [repUrl, setRepUrl] = useState("");
  const [repHeaders, setRepHeaders] = useState("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
  const [repBody, setRepBody] = useState("");
  const [repSending, setRepSending] = useState(false);
  const [repResponse, setRepResponse] = useState(null);
  const [repError, setRepError] = useState("");

  // Attack Tools: Brute Force state
  const [bfTarget, setBfTarget] = useState("");
  const [bfMethod, setBfMethod] = useState("POST");
  const [bfUserParam, setBfUserParam] = useState("username");
  const [bfPassParam, setBfPassParam] = useState("password");
  const [bfPosition, setBfPosition] = useState("body");
  const [bfMode, setBfMode] = useState("cluster_bomb");
  const [bfUsers, setBfUsers] = useState("admin\nadministrator\nroot\nuser");
  const [bfPasswords, setBfPasswords] = useState("password\n123456\nadmin\nletmein");
  const [bfFailure, setBfFailure] = useState("Invalid");
  const [bfSuccess, setBfSuccess] = useState("");
  const [bfHeaders, setBfHeaders] = useState("");
  const [bfBody, setBfBody] = useState("");
  const [bfPresets, setBfPresets] = useState({});
  const [bfRunning, setBfRunning] = useState(false);
  const [bfAttackId, setBfAttackId] = useState(null);
  const [bfResults, setBfResults] = useState([]);
  const [bfStatus, setBfStatus] = useState(null);
  const [bfError, setBfError] = useState("");

  // Attack Tools: Fuzzer state
  const [fuzzTarget, setFuzzTarget] = useState("");
  const [fuzzWordlist, setFuzzWordlist] = useState("");
  const [fuzzTests, setFuzzTests] = useState(["sqli", "xss", "lfi", "redirect"]);
  const [fuzzMaxEndpoints, setFuzzMaxEndpoints] = useState(12);
  const [fuzzRunning, setFuzzRunning] = useState(false);
  const [fuzzJobId, setFuzzJobId] = useState(null);
  const [fuzzStatus, setFuzzStatus] = useState(null);
  const [fuzzError, setFuzzError] = useState("");


  // Encoder/Decoder state
  const [edPayload, setEdPayload] = useState("");
  const [edResult, setEdResult] = useState("");
  const [edEncodingType, setEdEncodingType] = useState("url");
  const [edDecodingType, setEdDecodingType] = useState("url");
  const [edLoading, setEdLoading] = useState(false);
  const [edError, setEdError] = useState("");
  const [edAvailableEncodings, setEdAvailableEncodings] = useState({ encodings: [], decodings: [] });
  const [edBruteResults, setEdBruteResults] = useState(null);

  // Fetch AI providers on mount
  // Fetch AI providers on mount
  useEffect(() => {
    fetchAIProviders();
  }, []);

  const fetchAIProviders = async () => {
    try {
      const response = await axios.get("/api/ai/providers");
      setAiProviders(response.data.providers || []);
      if (response.data.providers && response.data.providers.length > 0) {
        setSelectedProvider(response.data.providers[0].id);
        setSelectedModel(response.data.providers[0].default_model);
      }
    } catch (err) {
      console.error("Failed to fetch AI providers:", err);
    }
  };

  const fetchAvailableEncodings = async () => {
    try {
      const response = await axios.get("/api/encodings");
      setEdAvailableEncodings(response.data);
    } catch (err) {
      console.error("Failed to fetch available encodings:", err);
    }
  };

  useEffect(() => {
    fetchAvailableEncodings();
  }, []);

  const handleEncode = async () => {
    if (!edPayload) {
      setEdError("Please enter a payload to encode");
      return;
    }
    setEdLoading(true);
    setEdError("");
    setEdResult("");
    setEdBruteResults(null);
    try {
      const response = await axios.post("/api/encode", {
        payload: edPayload,
        encoding_type: edEncodingType,
      });
      setEdResult(response.data.encoded);
    } catch (err) {
      setEdError(err.response?.data?.error || "Encoding failed");
    } finally {
      setEdLoading(false);
    }
  };

  const handleDecode = async () => {
    if (!edPayload) {
      setEdError("Please enter a payload to decode");
      return;
    }
    setEdLoading(true);
    setEdError("");
    setEdResult("");
    setEdBruteResults(null);
    try {
      const response = await axios.post("/api/decode", {
        payload: edPayload,
        decoding_type: edDecodingType,
      });
      setEdResult(response.data.decoded);
    } catch (err) {
      setEdError(err.response?.data?.error || "Decoding failed");
    } finally {
      setEdLoading(false);
    }
  };

  const handleSmartDecode = async () => {
    if (!edPayload) {
      setEdError("Please enter a payload to decode");
      return;
    }
    setEdLoading(true);
    setEdError("");
    setEdResult("");
    setEdBruteResults(null);
    try {
      const response = await axios.post("/api/decode/smart", {
        payload: edPayload,
      });
      setEdResult(response.data.decoded);
    } catch (err) {
      setEdError(err.response?.data?.error || "Smart decode failed");
    } finally {
      setEdLoading(false);
    }
  };

  const handleBruteDecode = async () => {
    if (!edPayload) {
      setEdError("Please enter a payload to decode");
      return;
    }
    setEdLoading(true);
    setEdError("");
    setEdResult("");
    setEdBruteResults(null);
    try {
      const response = await axios.post("/api/decode/brute", {
        payload: edPayload,
      });
      setEdBruteResults(response.data.results);
    } catch (err) {
      setEdError(err.response?.data?.error || "Brute force decode failed");
    } finally {
      setEdLoading(false);
    }
  };

  const handleDetect = async () => {
    if (!edPayload) {
      setEdError("Please enter a payload to detect");
      return;
    }
    setEdLoading(true);
    setEdError("");
    setEdResult("");
    setEdBruteResults(null);
    try {
      const response = await axios.post("/api/detect", {
        payload: edPayload,
      });
      setEdResult(`[${response.data.detected_encoding}] ${response.data.decoded}`);
    } catch (err) {
      setEdError(err.response?.data?.error || "Detection failed");
    } finally {
      setEdLoading(false);
    }
  };

  // The status/tool polling effects live further down the file, after the
  // checkScanStatus/poll* functions they reference (a const referenced before
  // its declaration would throw at render time).

  // Auto-fill tool targets from the main target URL
  useEffect(() => {
    if (targetUrl) {
      setIntruderTarget(targetUrl);
      setRepUrl(targetUrl);
      setBfTarget(targetUrl);
      setFuzzTarget(targetUrl);
      setPdTarget(targetUrl);
      setTfTarget(targetUrl);
    }
  }, [targetUrl]);

  // Load built-in payload presets when the Brute Force tab opens
  useEffect(() => {
    if (toolsTab === 2 && Object.keys(bfPresets).length === 0) {
      axios
        .get("/api/intruder/presets")
        .then((res) => setBfPresets(res.data))
        .catch((err) => console.error("Failed to load payload presets:", err));
    }
  }, [toolsTab, bfPresets]);

  const handleStartScan = async () => {
    if (!targetUrl) {
      setError("Please enter a target URL or IP");
      return;
    }
    
    if (selectedModules.length === 0) {
      setError("Please select at least one scan module");
      return;
    }
    
    try {
      setError("");
      setScanStatus("running");
      setResults(null);
      
      const response = await axios.post("/api/scan", {
        target_url: targetUrl,
        modules: selectedModules,
      });
      
      setScanId(response.data.scan_id);
      showToast("Scan started against " + targetUrl, "info");
      setActiveScans((prev) => ({
        ...prev,
        [response.data.scan_id]: {
          target: response.data.target,
          modules: response.data.modules,
          status: "running",
          started_at: new Date().toISOString(),
        },
      }));
    } catch (err) {
      setError(err.response?.data?.error || "Failed to start scan");
      setScanStatus("idle");
    }
  };

  // Run every scan module against the target with a single click.
  const handleRunAllScans = async () => {
    if (!targetUrl) {
      setError("Please enter a target URL or IP");
      return;
    }

    try {
      setError("");
      setAllScansRunning(true);
      setAllScanProgress({});

      const response = await axios.post("/api/scan/all", {
        target_url: targetUrl,
      });

      const scanIds = response.data.scan_ids || [response.data.scan_id];

      // Track every launched scan so the UI can follow them all
      setActiveScans((prev) => {
        const next = { ...prev };
        scanIds.forEach((id, index) => {
          next[id] = {
            target: response.data.targets?.[index] || targetUrl,
            modules: response.data.modules,
            status: "running",
            progress: 0,
            current_step: "Initializing scanners...",
            started_at: new Date().toISOString(),
          };
        });
        return next;
      });

      // Follow the first scan; it represents the batch in the UI
      setScanId(response.data.scan_id);
      showToast("Full scan started against " + targetUrl, "info");
      setScanStatus("running");
      setResults(null);
    } catch (err) {
      setAllScansRunning(false);
      setError(err.response?.data?.error || "Failed to start the full scan");
    }
  };

  // Stop a running scan; the current module finishes first.
  const handleStopScan = async () => {
    if (!scanId) return;
    try {
      const response = await axios.post(`/api/scan/${scanId}/stop`);
      setError("");
      setActiveScans((prev) => ({
        ...prev,
        [scanId]: {
          ...prev[scanId],
          current_step: response.data.message || "Stopping...",
        },
      }));
    } catch (err) {
      setError(err.response?.data?.error || "Failed to stop the scan");
    }
  };

  // Wrapped in useCallback so the status-polling effect below always calls the
  // freshest closure; otherwise the interval would capture a stale `scanId`
  // and keep polling an old scan after a new one starts.
  const fetchResults = useCallback(async () => {
    try {
      const response = await axios.get(`/api/scan/${scanId}/results`);
      setResults(response.data);
      showToast("Scan results ready", "success");
    } catch (err) {
      setError("Failed to fetch results");
    }
  }, [scanId, showToast]);

  const checkScanStatus = useCallback(async () => {
    try {
      const response = await axios.get(`/api/scan/${scanId}/status`);
      setActiveScans((prev) => ({
        ...prev,
        [scanId]: { ...prev[scanId], ...response.data },
      }));

      // Surface per-module progress for the one-click "run all" view
      if (response.data.module_status) {
        setAllScanProgress(response.data.module_status);
      }

      if (response.data.status === "completed") {
        setScanStatus("completed");
        setAllScansRunning(false);
        fetchResults();
      } else if (response.data.status === "cancelled") {
        setScanStatus("cancelled");
        setAllScansRunning(false);
        // Keep whatever was collected before the stop
        fetchResults();
      } else if (response.data.status === "error") {
        setScanStatus("error");
        setAllScansRunning(false);
        setError(response.data.error || "Scan failed");
      }
    } catch (err) {
      console.error("Status check error:", err);
    }
  }, [scanId, fetchResults]);

  const downloadReport = async () => {
    try {
      const response = await axios.get(`/api/scan/${scanId}/report`);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute(
        "download",
        `red_dragon_report_${scanId}.html`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError("Failed to download report");
    }
  };

  // Open the results-only window for the current scan. The desktop shell owns
  // the extra window (popups are denied at the webContents level); in a plain
  // browser during development, window.open is the fallback.
  const openResultsWindow = async () => {
    if (!scanId) return;
    if (IS_DESKTOP && window.redDragon?.openResultsWindow) {
      await window.redDragon.openResultsWindow(scanId);
    } else {
      window.open(
        `/?view=results&scanId=${encodeURIComponent(scanId)}`,
        "red-dragon-results",
        "width=1280,height=900"
      );
    }
  };

  const toggleModule = (moduleId) => {
    if (moduleId === "all") {
      setSelectedModules(["all"]);
      return;
    }
    
    setSelectedModules((prev) => {
      const withoutAll = prev.filter((m) => m !== "all");
      
      if (withoutAll.includes(moduleId)) {
        const newModules = withoutAll.filter((m) => m !== moduleId);
        return newModules.length === 0 ? ["all"] : newModules;
      } else {
        return [...withoutAll, moduleId];
      }
    });
  };

  const prepareChartData = () => {
    if (!results || !results.findings) return [];
    const findings = results.findings;
    const data = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0,
    };
    findings.forEach((f) => {
      const severity = f.severity || "Info";
      if (severity in data) data[severity]++;
    });
    return Object.entries(data).map(([name, value]) => ({ name, value }));
  };

    const chartData = prepareChartData();

  // --- Graph helpers for criticality-based visualizations ---

  // Group findings by vulnerability type, tracking the highest severity per type
  const prepareTypeData = () => {
    if (!results || !results.findings) return [];
    const sevOrder = ["Critical", "High", "Medium", "Low", "Info"];
    const typeMap = {};
    results.findings.forEach((f) => {
      const typeName = f.type || "Unknown";
      if (!typeMap[typeName]) {
        typeMap[typeName] = { name: typeName, count: 0, highestSeverity: "Info" };
      }
      typeMap[typeName].count += 1;
      if (sevOrder.indexOf(f.severity) < sevOrder.indexOf(typeMap[typeName].highestSeverity)) {
        typeMap[typeName].highestSeverity = f.severity;
      }
    });
    // Sort by count descending so the most critical types are most prominent
    return Object.values(typeMap).sort((a, b) => b.count - a.count);
  };
  const typeData = prepareTypeData();

  // Compute an overall risk score (weighted average of severity ranks, 0-100)
  const calculateRiskScore = () => {
    if (!results || !results.findings || results.findings.length === 0)
      return { score: 0, level: "None", color: "#16a34a" };
    const sevWeight = { Critical: 100, High: 75, Medium: 50, Low: 25, Info: 10 };
    let total = 0;
    results.findings.forEach((f) => {
      total += sevWeight[f.severity] || 10;
    });
    const avg = Math.round(total / results.findings.length);
    const score = Math.min(100, avg);
    const level =
      score >= 80 ? "Critical" :
      score >= 60 ? "High" :
      score >= 40 ? "Medium" :
      score > 0 ? "Low" : "None";
    return { score, level, color: getSeverityColor(level) };
  };
  const riskScore = calculateRiskScore();

  // AI Chat functions
  const openAIChat = () => {
    setAiDialogOpen(true);
    setAiMessages([]);
  };

  const sendAIMessage = async () => {
    if (!aiInput.trim()) return;
    
    if (isCustomModel && !selectedModel.trim()) {
      setAiMessages((prev) => [...prev, { role: "assistant", content: "Error: enter a model name, or pick a preset model." }]);
      return;
    }

    // Configure AI provider if not already done
    if (aiApiKey && selectedProvider) {
      try {
        const configResponse = await axios.post("/api/ai/configure", {
          provider: selectedProvider,
          api_key: aiApiKey,
          model: (selectedModel || "").trim() || undefined,
        });
        if (configResponse.data && configResponse.data.success === false) {
          // Stop rather than chatting with a stale or default model the
          // user did not pick (e.g. a malformed custom model name).
          setAiMessages((prev) => [...prev, { role: "assistant", content: `Error: ${configResponse.data.error}` }]);
          return;
        }
      } catch (err) {
        console.error("Failed to configure AI:", err);
      }
    }
    
    const userMessage = aiInput;
    setAiInput("");
    setAiMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setAiLoading(true);
    
    try {
      const response = await axios.post("/api/ai/chat", {
        message: userMessage,
        provider: selectedProvider,
        api_key: aiApiKey || undefined,
        model: (selectedModel || "").trim() || undefined,
        scan_context: results || undefined,
      });
      
      if (response.data.error) {
        setAiMessages((prev) => [...prev, { role: "assistant", content: `Error: ${response.data.error}` }]);
      } else {
        setAiMessages((prev) => [...prev, { role: "assistant", content: response.data.reply || response.data.analysis }]);
      }
    } catch (err) {
      setAiMessages((prev) => [...prev, { role: "assistant", content: `Error: ${err.response?.data?.error || err.message}` }]);
    }
    
    setAiLoading(false);
  };

  // Discover the parameters a target accepts, on demand.
  const handleParameterDiscovery = async () => {
    const target = (pdTarget || "").trim();
    if (!target) {
      setPdError("Please enter a target URL");
      return;
    }

    try {
      setPdError("");
      setPdLoading(true);
      setPdResult(null);

      const response = await axios.post("/api/parameters", {
        target_url: target,
      });

      setPdResult(response.data);
    } catch (err) {
      setPdError(err.response?.data?.error || "Parameter discovery failed");
    } finally {
      setPdLoading(false);
    }
  };

  // Fingerprint the target's architecture on demand.
  const handleFingerprint = async () => {
    const target = (tfTarget || "").trim();
    if (!target) {
      setTfError("Please enter a target URL");
      return;
    }

    try {
      setTfError("");
      setTfLoading(true);
      setTfResult(null);

      const response = await axios.post("/api/technology", {
        target_url: target,
      });

      setTfResult(response.data);
    } catch (err) {
      setTfError(err.response?.data?.error || "Fingerprinting failed");
    } finally {
      setTfLoading(false);
    }
  };

  // ============ AI Security Agent ============

  // Create (or re-key) an agent session using the user's own API key.
  const handleAgentConnect = async () => {
    if (!selectedProvider) {
      setAgentError("Select a provider first");
      return;
    }
    if (isCustomModel && !selectedModel.trim()) {
      setAgentError("Enter a model name, or pick a preset model");
      return;
    }
    if (!agentKey.trim()) {
      setAgentError("Enter your API key");
      return;
    }

    try {
      setAgentError("");
      setAgentBusy(true);
      setAgentStatus("Connecting...");

      const response = await axios.post("/api/ai/session", {
        provider: selectedProvider,
        api_key: agentKey.trim(),
        model: (selectedModel || "").trim() || undefined,
        session_id: agentSession || undefined,
      });

      if (response.data.verified) {
        setAgentSession(response.data.session_id);
        setAgentStatus(
          `Connected to ${response.data.provider_name} (${response.data.model})`
        );
        // The key has been handed to the backend; drop it from component state
        setAgentKey("");
      } else {
        setAgentStatus("");
        setAgentError(
          response.data.warning || "The provider rejected the API key"
        );
      }
    } catch (err) {
      setAgentStatus("");
      setAgentError(
        err.response?.data?.error || "Could not start the AI session"
      );
    } finally {
      setAgentBusy(false);
    }
  };

  // End the session, which discards the key held on the server.
  const handleAgentDisconnect = async () => {
    if (agentSession) {
      try {
        await axios.delete(`/api/ai/session/${agentSession}`);
      } catch (err) {
        // Best effort - the key expires with the session regardless
      }
    }
    setAgentSession(null);
    setAgentStatus("");
    setAgentMessages([]);
    setAgentReport("");
    setAgentAuthorised(false);
  };

  // Run the selected agent action against the current scan results.
  const handleAgentRun = async () => {
    if (!agentSession) {
      setAgentError("Connect to a provider first");
      return;
    }
    if (agentMode === "ask" && !agentQuestion.trim()) {
      setAgentError("Enter a question");
      return;
    }

    const endpoint =
      agentMode === "ask"
        ? "/api/ai/agent/ask"
        : agentMode === "report"
        ? "/api/ai/agent/report"
        : "/api/ai/agent/attack-plan";

    const payload = {
      session_id: agentSession,
      scan_id: scanId || undefined,
      // Fall back to sending the results if the server no longer has the scan
      scan_results: scanId ? undefined : results || undefined,
    };

    if (agentMode === "ask") {
      payload.question = agentQuestion.trim();
      setAgentMessages((prev) => [
        ...prev,
        { role: "user", content: agentQuestion.trim() },
      ]);
      setAgentQuestion("");
    }
    if (agentMode === "report") {
      payload.audience = agentAudience;
    }
    if (agentMode === "attack") {
      payload.authorised = agentAuthorised;
      payload.scope_note = agentScope;
    }

    try {
      setAgentError("");
      setAgentBusy(true);

      const response = await axios.post(endpoint, payload);

      const text = response.data.reply || "";
      if (agentMode === "report" || agentMode === "attack") {
        setAgentReport(text);
      } else {
        setAgentMessages((prev) => [...prev, { role: "assistant", content: text }]);
      }

      if (!response.data.used_scan_context) {
        setAgentError(
          "No scan results were available, so the answer is general rather than target-specific."
        );
      }
    } catch (err) {
      setAgentError(err.response?.data?.error || "The AI request failed");
    } finally {
      setAgentBusy(false);
    }
  };

  // Download the generated report as a markdown file.
  const handleAgentDownload = () => {
    if (!agentReport) return;
    const blob = new Blob([agentReport], { type: "text/markdown" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `red_dragon_ai_report_${scanId || "scan"}.md`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  // Run AI analysis handler follows
  const runAIAnalysis = async () => {
    if (!results) {
      setError("No scan results available. Please run a scan first.");
      return;
    }
    
    if (!aiApiKey) {
      setError("Please enter your AI API key");
      return;
    }
    
    if (!selectedProvider) {
      setError("Please select an AI provider");
      return;
    }

    if (isCustomModel && !selectedModel.trim()) {
      setError("Enter a model name, or pick a preset model");
      return;
    }
    
    setAiAnalyzing(true);
    setAiDialogOpen(true);
    setAiMessages((prev) => [...prev, { role: "user", content: "Analyze these scan results and provide a comprehensive security analysis." }]);
    
    try {
      const response = await axios.post("/api/ai/analyze", {
        scan_results: results,
        provider: selectedProvider,
        api_key: aiApiKey,
        model: (selectedModel || "").trim() || undefined,
      });
      
      if (response.data.error) {
        setAiMessages((prev) => [...prev, { role: "assistant", content: `Error: ${response.data.error}` }]);
      } else {
        setAiMessages((prev) => [...prev, { role: "assistant", content: response.data.analysis }]);
      }
    } catch (err) {
      setAiMessages((prev) => [...prev, { role: "assistant", content: `Error: ${err.response?.data?.error || err.message}` }]);
    }
    
    setAiAnalyzing(false);
  };

  // Source Analyzer: fetch a website's source code and analyze it
  const analyzeSource = async () => {
    const url = (saUrl.trim() || targetUrl.trim());
    if (!url) {
      setSaError("Please enter a URL to analyze");
      return;
    }
    setSaLoading(true);
    setSaError("");
    setSaResult(null);
    setSaShowSource(false);
    try {
      const response = await axios.post("/api/source/fetch", { url });
      setSaResult(response.data);
    } catch (err) {
      setSaError(err.response?.data?.error || "Failed to fetch website source");
    }
    setSaLoading(false);
  };

  // ============ Attack Tools: Intruder ============
  const parseHeaders = (text) => {
    const headers = {};
    text.split("\n").forEach((line) => {
      const idx = line.indexOf(":");
      if (idx > 0) {
        headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });
    return headers;
  };

  const startIntruderAttack = async () => {
    if (!intruderTarget) {
      setIntruderError("Target URL is required");
      return;
    }
    const payloads = [payloadSet1.split("\n").map((p) => p.trim()).filter(Boolean)];
    if (payloadSet2.trim()) {
      payloads.push(payloadSet2.split("\n").map((p) => p.trim()).filter(Boolean));
    }
    const parameters = intruderParams
      .split(",")
      .map((n) => n.trim())
      .filter(Boolean)
      .map((name) => ({ name, position: intruderParamPos }));
    if (parameters.length === 0) {
      setIntruderError("At least one parameter is required");
      return;
    }
    try {
      setIntruderError("");
      const response = await axios.post("/api/intruder/start", {
        target_url: intruderTarget,
        attack_type: intruderAttackType,
        method: intruderMethod,
        parameters,
        payloads,
        match_type: matchType,
        match_value: matchValue,
        headers: parseHeaders(intruderHeaders),
        body: intruderBody || null,
      });
      setIntruderAttackId(response.data.attack_id);
      setIntruderResults([]);
      setIntruderStatus(null);
      setIntruderRunning(true);
    } catch (err) {
      setIntruderError(err.response?.data?.error || "Failed to start attack");
    }
  };

  // useCallback so the polling intervals always see the current attack ids.
  const pollIntruderStatus = useCallback(async () => {
    if (!intruderAttackId) return;
    try {
      const response = await axios.get(`/api/intruder/status/${intruderAttackId}`);
      setIntruderStatus(response.data);
      setIntruderResults(response.data.results || []);
      if (!response.data.is_running) {
        setIntruderRunning(false);
      }
    } catch (err) {
      console.error("Intruder status poll failed:", err);
    }
  }, [intruderAttackId]);

  const stopIntruderAttack = async () => {
    if (intruderAttackId) {
      try {
        await axios.post(`/api/intruder/stop/${intruderAttackId}`);
      } catch (err) {
        console.error("Failed to stop attack:", err);
      }
      setIntruderRunning(false);
    }
  };

  // ============ Attack Tools: Brute Force ============
  const pollBruteForceStatus = useCallback(async () => {
    if (!bfAttackId) return;
    try {
      const response = await axios.get(`/api/intruder/status/${bfAttackId}`);
      setBfStatus(response.data);
      setBfResults(response.data.results || []);
      if (!response.data.is_running) {
        setBfRunning(false);
      }
    } catch (err) {
      console.error("Brute force status poll failed:", err);
    }
  }, [bfAttackId]);

  const appendPreset = (presetKey, setter) => {
    const preset = bfPresets[presetKey];
    if (!preset) return;
    setter((prev) => (prev.trim() ? prev.trimEnd() + "\n" : "") + preset.items.join("\n"));
  };

  const startBruteForce = async () => {
    if (!bfTarget) {
      setBfError("Login URL is required");
      return;
    }
    const users = bfUsers.split("\n").map((u) => u.trim()).filter(Boolean);
    const passwords = bfPasswords.split("\n").map((p) => p.trim()).filter(Boolean);
    if (users.length === 0 || passwords.length === 0) {
      setBfError("Both username and password lists are required");
      return;
    }
    try {
      setBfError("");
      const response = await axios.post("/api/intruder/bruteforce", {
        target_url: bfTarget,
        method: bfMethod,
        username_param: bfUserParam,
        password_param: bfPassParam,
        position: bfPosition,
        attack_mode: bfMode,
        failure_indicator: bfFailure,
        success_indicator: bfSuccess,
        users,
        passwords,
        headers: parseHeaders(bfHeaders),
        body: bfBody || null,
      });
      setBfAttackId(response.data.attack_id);
      setBfResults([]);
      setBfStatus(null);
      setBfRunning(true);
    } catch (err) {
      setBfError(err.response?.data?.error || "Failed to start brute force attack");
    }
  };

  const stopBruteForce = async () => {
    if (bfAttackId) {
      try {
        await axios.post(`/api/intruder/stop/${bfAttackId}`);
      } catch (err) {
        console.error("Failed to stop brute force attack:", err);
      }
      setBfRunning(false);
    }
  };

  // ============ Attack Tools: Fuzzer ============
  const pollFuzzerStatus = useCallback(async () => {
    if (!fuzzJobId) return;
    try {
      const response = await axios.get(`/api/fuzz/attack/${fuzzJobId}`);
      setFuzzStatus(response.data);
      if (response.data.status !== "running") {
        setFuzzRunning(false);
      }
    } catch (err) {
      console.error("Fuzzer status poll failed:", err);
    }
  }, [fuzzJobId]);

  // ---- Status/tool polling (declared after the pollers above so no TDZ) ----
  useEffect(() => {
    if (!scanId || scanStatus !== "running") return;
    const id = setInterval(checkScanStatus, 3000);
    checkScanStatus();
    return () => clearInterval(id);
  }, [scanId, scanStatus, checkScanStatus]);

  useEffect(() => {
    if (!intruderRunning || !intruderAttackId) return;
    const id = setInterval(pollIntruderStatus, 2000);
    pollIntruderStatus();
    return () => clearInterval(id);
  }, [intruderRunning, intruderAttackId, pollIntruderStatus]);

  useEffect(() => {
    if (!bfRunning || !bfAttackId) return;
    const id = setInterval(pollBruteForceStatus, 2000);
    pollBruteForceStatus();
    return () => clearInterval(id);
  }, [bfRunning, bfAttackId, pollBruteForceStatus]);

  useEffect(() => {
    if (!fuzzRunning || !fuzzJobId) return;
    const id = setInterval(pollFuzzerStatus, 2500);
    pollFuzzerStatus();
    return () => clearInterval(id);
  }, [fuzzRunning, fuzzJobId, pollFuzzerStatus]);

  const toggleFuzzTest = (testId) => {
    setFuzzTests((prev) =>
      prev.includes(testId) ? prev.filter((t) => t !== testId) : [...prev, testId]
    );
  };

  const startFuzzer = async () => {
    if (!fuzzTarget) {
      setFuzzError("Target URL is required");
      return;
    }
    if (fuzzTests.length === 0) {
      setFuzzError("Select at least one vulnerability test");
      return;
    }
    try {
      setFuzzError("");
      const response = await axios.post("/api/fuzz/attack", {
        target_url: fuzzTarget,
        wordlist: fuzzWordlist || null,
        vuln_tests: fuzzTests,
        max_endpoints: Number(fuzzMaxEndpoints) || 12,
      });
      setFuzzJobId(response.data.job_id);
      setFuzzStatus(null);
      setFuzzRunning(true);
    } catch (err) {
      setFuzzError(err.response?.data?.error || "Failed to start fuzzing");
    }
  };

  // ============ Attack Tools: Repeater ============
  const sendRepeaterRequest = async () => {
    if (!repUrl) {
      setRepError("URL is required");
      return;
    }
    try {
      setRepError("");
      setRepSending(true);
      setRepResponse(null);
      const response = await axios.post("/api/repeater/send", {
        method: repMethod,
        url: repUrl,
        headers: parseHeaders(repHeaders),
        body: repBody || null,
      });
      setRepResponse(response.data);
    } catch (err) {
      setRepError(err.response?.data?.error || err.message || "Request failed");
    } finally {
      setRepSending(false);
    }
  };

  return (
    <Box sx={{ flexGrow: 1, bgcolor: themeMode === "dark" ? "#0A0A0B" : "#FFFFFF", minHeight: "100vh" }}>
      <AppBar position="sticky" sx={{ 
        bgcolor: themeMode === "dark" ? "rgba(10, 10, 11, 0.72)" : "rgba(255, 255, 255, 0.72)", 
        backdropFilter: "blur(20px) saturate(180%)",
        WebkitBackdropFilter: "blur(20px) saturate(180%)",
        boxShadow: "none",
        borderBottom: themeMode === "dark" ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid rgba(0, 0, 0, 0.08)"
      }}>
        <Toolbar>
          <SecurityIcon sx={{ mr: 1.5, fontSize: 32, color: themeMode === "dark" ? "#FF6F61" : "#E53935" }} />
          <Typography
            variant="h5"
            component="div"
            sx={{
              flexGrow: 1,
              fontWeight: 800,
              letterSpacing: "1.5px",
              background: "linear-gradient(90deg, #B71C1C 0%, #E53935 55%, #FF6F61 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}
          >
            RED DRAGON
          </Typography>
          <img
            src="/logo.png"
            alt="Aegis Cyber Works Logo"
            style={{ width: 24, height: 24, objectFit: "contain", marginRight: 8 }}
          />
          <Chip
            size="small"
            icon={<BugIcon sx={{ fontSize: 16, color: "#FFF !important" }} />}
            label="by aegis cyber works"
            sx={{ bgcolor: themeMode === "dark" ? "#FF6F61" : "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", boxShadow: themeMode === "dark" ? "0 2px 8px rgba(0,212,255,0.35)" : "0 2px 8px rgba(229,57,53,0.35)" }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Typography variant="caption" sx={{ color: themeMode === "dark" ? "#A0A0A0" : "#6E6E73", display: { xs: "hidden", sm: "block" } }}>
              {themeMode === "dark" ? "Dark Mode" : "Light Mode"}
            </Typography>
            <IconButton
              size="small"
              onClick={() => setThemeMode(themeMode === "dark" ? "light" : "dark")}
              sx={{
                color: themeMode === "dark" ? "#FFFFFF" : "#1D1D1F",
                bgcolor: themeMode === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)",
                "&:hover": { bgcolor: themeMode === "dark" ? "rgba(255,255,255,0.16)" : "rgba(0,0,0,0.12)" },
              }}
              title={`Switch to ${themeMode === "dark" ? "light" : "dark"} mode`}
            >
              {themeMode === "dark" ? <LightModeIcon fontSize="small" /> : <DarkModeIcon fontSize="small" />}
            </IconButton>
          </Box>
        </Toolbar>
      </AppBar>

      <Box className="section">
        {error && (
          <Alert severity="error" sx={{ mb: 3, borderRadius: 3 }} onClose={() => setError("")}>
            {error}
          </Alert>
        )}

        {/* Target Configuration Card */}
        <Paper sx={{ 
          p: 4, 
          mb: 4, 
          bgcolor: "#FFF", 
          border: "1px solid rgba(0, 0, 0, 0.08)",
          borderRadius: 4,
          boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)"
        }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, pb: 2, borderBottom: themeMode === "dark" ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid rgba(0, 0, 0, 0.08)", position: "relative" }}>
            <SettingsIcon sx={{ color: "#E53935", fontSize: 28 }} />
            <Typography variant="h4" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
              Target Configuration
            </Typography>
            <Box sx={{ position: "absolute", bottom: -1, left: 0, width: 72, height: 3, borderRadius: "3px 3px 0 0", background: "linear-gradient(90deg, #E53935, #FF8A80)" }} />
          </Box>
          
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={4}>
               <Box className="input-group">
                 <label className="input-label">Scan Mode</label>
                 <Select
                   value={scanMode}
                   label="Scan Mode"
                   onChange={(e) => setScanMode(e.target.value)}
                   sx={{
                     "& .MuiInputBase-root": { bgcolor: "#F5F5F7", color: "#1D1D1F", borderRadius: 2 },
                     "& .MuiInputLabel-root": { color: "#6E6E73" },
                     "& .MuiOutlinedInput-root": {
                       "&:hover fieldset": { borderColor: "#E53935" },
                       "&.Mui-focused fieldset": { borderColor: "#E53935" },
                     },
                   }}
                 >
                   <MenuItem value="url">URL Scan</MenuItem>
                   <MenuItem value="ip">IP Scan</MenuItem>
                 </Select>
               </Box>
            </Grid>
            
            <Grid item xs={12} md={4}>
               <TextField
                 fullWidth
                 label={scanMode === "ip" ? "IP Address" : "Target URL"}
                 placeholder={scanMode === "ip" ? "192.168.1.1" : "https://example.com"}
                 value={targetUrl}
                 onChange={(e) => setTargetUrl(e.target.value)}
                 sx={{
                   "& .MuiInputBase-root": { bgcolor: "#F5F5F7", color: "#1D1D1F", borderRadius: 2 },
                   "& .MuiInputLabel-root": { color: "#6E6E73" },
                   "& .MuiOutlinedInput-root": {
                     fieldset: { borderColor: "rgba(0, 0, 0, 0.08)" },
                     "&:hover fieldset": { borderColor: "#E53935" },
                     "&.Mui-focused fieldset": { borderColor: "#E53935" },
                   },
                 }}
               />
             </Grid>
            
             <Grid item xs={12} md={4}>
               <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                 <Button
                   variant="contained"
                   onClick={handleStartScan}
                   disabled={scanStatus === "running"}
                   startIcon={<SendIcon />}
                   sx={{
                     bgcolor: "#E53935",
                     color: "#FFF",
                     fontWeight: "bold",
                     borderRadius: "999px",
                     px: 3,
                     py: 1,
                     "&:hover": { bgcolor: "#F44336", transform: "translateY(-2px)", boxShadow: "0 4px 12px rgba(229, 57, 53, 0.3)" },
                     "&:disabled": { bgcolor: "#E5E5E5", color: "#999" },
                   }}
                 >
                   {scanStatus === "running" ? "Scanning..." : "Start Scan"}
                 </Button>
                  <Button
                    variant="contained"
                    onClick={handleRunAllScans}
                    disabled={allScansRunning || !targetUrl}
                    startIcon={<AIIcon />}
                    sx={{
                      bgcolor: "#1D1D1F",
                      color: "#FFF",
                      fontWeight: "bold",
                      borderRadius: "999px",
                      px: 3,
                      py: 1,
                      "&:hover": { bgcolor: "#000", transform: "translateY(-2px)", boxShadow: "0 4px 12px rgba(0, 0, 0, 0.3)" },
                      "&:disabled": { bgcolor: "#E5E5E5", color: "#999" },
                    }}
                  >
                    {allScansRunning ? "Running all..." : "Run All Scans"}
                  </Button>
                  {scanStatus === "running" && (
                    <Button
                      variant="outlined"
                      onClick={handleStopScan}
                      startIcon={<DeleteIcon />}
                      sx={{
                        color: "#E53935",
                        borderColor: "#E53935",
                        borderRadius: "999px",
                        px: 3,
                        py: 1,
                      }}
                    >
                      Stop
                    </Button>
                  )}
                 <Button
                   variant="outlined"
                   onClick={() => setModulesDialogOpen(true)}
                   startIcon={<SettingsIcon />}
                   sx={{ 
                     color: "#E53935", 
                     borderColor: "#E53935",
                     borderRadius: "999px",
                     px: 3,
                     py: 1,
                   }}
                 >
                   Modules ({selectedModules.includes("all") ? "All" : selectedModules.length})
                 </Button>
               </Box>
             </Grid>
          </Grid>
          
           {/* Selected modules chips */}
           <Box sx={{ mt: 3, display: "flex", flexWrap: "wrap", gap: 1 }}>
             {selectedModules.map((mod) => {
               const module = SCAN_MODULES.find((m) => m.id === mod);
               return (
                 <Chip
                   key={mod}
                   label={module?.name || mod}
                   onDelete={() => toggleModule(mod)}
                   sx={{
                     bgcolor: "#E53935",
                     color: "#FFF",
                     borderRadius: "999px",
                     fontWeight: 600,
                     "& .MuiChip-deleteIcon": { color: "#FFF" },
                   }}
                 />
               );
             })}
           </Box>
         </Paper>

        {/* Attack Tools: Intruder & Repeater */}
        <Paper sx={{ p: 4, mb: 4, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, pb: 2, borderBottom: themeMode === "dark" ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid rgba(0, 0, 0, 0.08)", position: "relative" }}>
            <HttpIcon sx={{ color: "#E53935", fontSize: 28 }} />
            <Typography variant="h4" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
              Attack Tools
            </Typography>
            <Box sx={{ position: "absolute", bottom: -1, left: 0, width: 72, height: 3, borderRadius: "3px 3px 0 0", background: "linear-gradient(90deg, #E53935, #FF8A80)" }} />
          </Box>
          <Tabs
            value={toolsTab}
            onChange={(e, v) => setToolsTab(v)}
            sx={{
              mb: 3,
              "& .MuiTab-root": { fontWeight: "bold", color: "#6E6E73" },
              "& .Mui-selected": { color: "#E53935" },
              "& .MuiTabs-indicator": { bgcolor: "#E53935" },
            }}
          >
            <Tab label="Intruder" />
            <Tab label="Repeater" />
            <Tab label="Brute Force" />
            <Tab label="Source Analyzer" />
            <Tab label="Fuzzer" />
            <Tab label="Parameters" />
            <Tab label="Architecture" />
            <Tab label="AI Agent" />
          </Tabs>

          {toolsTab === 0 && (
            <Box>
              {intruderError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setIntruderError("")}>
                  {intruderError}
                </Alert>
              )}
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField fullWidth size="small" label="Target URL" placeholder="https://example.com/page?id=1" value={intruderTarget} onChange={(e) => setIntruderTarget(e.target.value)} />
                </Grid>
                <Grid item xs={6} md={2}>
                  <Select fullWidth size="small" value={intruderMethod} onChange={(e) => setIntruderMethod(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="GET">GET</MenuItem>
                    <MenuItem value="POST">POST</MenuItem>
                    <MenuItem value="PUT">PUT</MenuItem>
                    <MenuItem value="DELETE">DELETE</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={6} md={4}>
                  <Select fullWidth size="small" value={intruderAttackType} onChange={(e) => setIntruderAttackType(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="sniper">Sniper (1 param, 1 payload set)</MenuItem>
                    <MenuItem value="cluster_bomb">Cluster Bomb (cross-product)</MenuItem>
                    <MenuItem value="pitchfork">Pitchfork (parallel sets)</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={6} md={4}>
                  <TextField fullWidth size="small" label="Parameters (comma-separated)" placeholder="id, user, page" value={intruderParams} onChange={(e) => setIntruderParams(e.target.value)} />
                </Grid>
                <Grid item xs={6} md={2}>
                  <Select fullWidth size="small" value={intruderParamPos} onChange={(e) => setIntruderParamPos(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="query">Query</MenuItem>
                    <MenuItem value="body">Body</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={5} label="Payload Set 1 (one per line)" value={payloadSet1} onChange={(e) => setPayloadSet1(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={5} label="Payload Set 2 (optional, for Cluster Bomb / Pitchfork)" value={payloadSet2} onChange={(e) => setPayloadSet2(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Select fullWidth size="small" value={matchType} onChange={(e) => setMatchType(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="contains">Contains</MenuItem>
                    <MenuItem value="not_contains">Does not contain</MenuItem>
                    <MenuItem value="status">Status code equals</MenuItem>
                    <MenuItem value="length">Length equals</MenuItem>
                    <MenuItem value="length_gt">Length greater than</MenuItem>
                    <MenuItem value="regex">Regex match</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={12} md={8}>
                  <TextField fullWidth size="small" label="Match value (e.g. 'admin', '200', '5000', '.*error.*')" value={matchValue} onChange={(e) => setMatchValue(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={2} label="Extra Headers (Key: Value per line)" value={intruderHeaders} onChange={(e) => setIntruderHeaders(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={2} label="Request Body (for POST/PUT)" value={intruderBody} onChange={(e) => setIntruderBody(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap" }}>
                    <Button variant="contained" onClick={startIntruderAttack} disabled={intruderRunning} startIcon={<SendIcon />} sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", px: 3, "&:hover": { bgcolor: "#F44336" }, "&:disabled": { bgcolor: "#E5E5E5", color: "#999" } }}>
                      {intruderRunning ? "Attacking..." : "Start Attack"}
                    </Button>
                    <Button variant="outlined" onClick={stopIntruderAttack} disabled={!intruderRunning} sx={{ color: "#E53935", borderColor: "#E53935", borderRadius: "999px" }}>
                      Stop
                    </Button>
                    {intruderStatus && (
                      <Chip
                        size="small"
                        label={`${intruderStatus.completed}/${intruderStatus.total_requests} requests | ${intruderStatus.matched} matched`}
                        sx={{ bgcolor: intruderRunning ? "#FFF3E0" : "#E8F5E9", color: intruderRunning ? "#E65100" : "#2E7D32", fontWeight: "bold" }}
                      />
                    )}
                  </Box>
                </Grid>
              </Grid>
              {intruderResults.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                    Attack Results ({intruderResults.length})
                  </Typography>
                  <Box sx={{ maxHeight: 400, overflow: "auto", border: "1px solid rgba(0,0,0,0.08)", borderRadius: 2 }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                      <thead>
                        <tr style={{ position: "sticky", top: 0, background: "#F5F5F7" }}>
                          <th style={{ padding: "8px 10px", textAlign: "left" }}>Payload</th>
                          <th style={{ padding: "8px 10px", textAlign: "left" }}>Status</th>
                          <th style={{ padding: "8px 10px", textAlign: "left" }}>Length</th>
                          <th style={{ padding: "8px 10px", textAlign: "left" }}>Time</th>
                          <th style={{ padding: "8px 10px", textAlign: "left" }}>Match</th>
                        </tr>
                      </thead>
                      <tbody>
                        {intruderResults.map((r, i) => (
                          <tr key={i} style={{ borderTop: "1px solid rgba(0,0,0,0.06)", background: r.matched ? "#FFF8E1" : "transparent", cursor: "pointer" }}
                            onClick={() => {
                              setRepMethod(r.method || "GET");
                              setRepUrl(r.url);
                              setRepBody(intruderBody);
                              setRepResponse({
                                status_code: r.status_code,
                                reason: r.error ? r.error : "",
                                response_body: r.response_snippet || "",
                                response_length: r.response_length,
                                elapsed: r.time,
                              });
                              setToolsTab(1);
                            }}>
                            <td style={{ padding: "8px 10px", fontFamily: "monospace" }}>{r.payload}</td>
                            <td style={{ padding: "8px 10px" }}>{r.status_code || "ERR"}</td>
                            <td style={{ padding: "8px 10px" }}>{r.response_length}</td>
                            <td style={{ padding: "8px 10px" }}>{r.time}</td>
                            <td style={{ padding: "8px 10px" }}>
                              {r.matched ? <Chip size="small" label="MATCH" sx={{ bgcolor: "#FFC107", fontWeight: "bold" }} /> : "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </Box>
                  <Typography variant="caption" sx={{ color: "#6E6E73" }}>
                    Click any row to send that request to the Repeater.
                  </Typography>
                </Box>
              )}
            </Box>
          )}
          {toolsTab === 1 && (
            <Box>
              {repError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setRepError("")}>
                  {repError}
                </Alert>
              )}
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField fullWidth size="small" label="Request URL" placeholder="https://example.com/page?id=1" value={repUrl} onChange={(e) => setRepUrl(e.target.value)} />
                </Grid>
                <Grid item xs={6} md={2}>
                  <Select fullWidth size="small" value={repMethod} onChange={(e) => setRepMethod(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="GET">GET</MenuItem>
                    <MenuItem value="POST">POST</MenuItem>
                    <MenuItem value="PUT">PUT</MenuItem>
                    <MenuItem value="DELETE">DELETE</MenuItem>
                    <MenuItem value="PATCH">PATCH</MenuItem>
                    <MenuItem value="HEAD">HEAD</MenuItem>
                    <MenuItem value="OPTIONS">OPTIONS</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={12} md={10}>
                  <TextField fullWidth size="small" multiline rows={2} label="Headers (Key: Value per line)" value={repHeaders} onChange={(e) => setRepHeaders(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <TextField fullWidth size="small" multiline rows={5} label="Request Body" value={repBody} onChange={(e) => setRepBody(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center" }}>
                    <Button variant="contained" onClick={sendRepeaterRequest} disabled={repSending} startIcon={<SendIcon />} sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", px: 3, "&:hover": { bgcolor: "#F44336" }, "&:disabled": { bgcolor: "#E5E5E5", color: "#999" } }}>
                      {repSending ? "Sending..." : "Send Request"}
                    </Button>
                    <Button variant="outlined" onClick={() => { setRepResponse(null); setRepError(""); }} sx={{ color: "#E53935", borderColor: "#E53935", borderRadius: "999px" }}>
                      Clear Response
                    </Button>
                  </Box>
                </Grid>
                {repResponse && (
                  <Grid item xs={12}>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 1, flexWrap: "wrap" }}>
                      <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                        Response
                      </Typography>
                      <Chip
                        size="small"
                        label={`${repResponse.status_code || "ERR"} ${repResponse.reason || ""} | ${repResponse.response_length ?? 0} bytes | ${repResponse.elapsed ?? "?"}s`.trim()}
                        sx={{
                          fontWeight: "bold",
                          bgcolor: repResponse.status_code >= 500 ? "#FFEBEE" : repResponse.status_code >= 400 ? "#FFF3E0" : repResponse.status_code >= 300 ? "#E3F2FD" : "#E8F5E9",
                          color: repResponse.status_code >= 500 ? "#C62828" : repResponse.status_code >= 400 ? "#E65100" : repResponse.status_code >= 300 ? "#1565C0" : "#2E7D32",
                        }}
                      />
                    </Box>
                    <Box sx={{ bgcolor: "#1D1D1F", color: "#A5D6A7", p: 2, borderRadius: 2, maxHeight: 400, overflow: "auto", fontFamily: "monospace", fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                      {repResponse.response_body || "(empty response body)"}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </Box>
          )}
          {toolsTab === 2 && (
            <Box>
              {bfError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setBfError("")}>
                  {bfError}
                </Alert>
              )}
              <Typography variant="body2" sx={{ color: "#6E6E73", mb: 2 }}>
                Burp Suite-style login brute force: combines a username list with a password list (Cluster Bomb or Pitchfork mode) and detects valid credentials using failure/success indicator strings.
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField fullWidth size="small" label="Login URL" placeholder="https://example.com/login" value={bfTarget} onChange={(e) => setBfTarget(e.target.value)} />
                </Grid>
                <Grid item xs={6} md={2}>
                  <Select fullWidth size="small" value={bfMethod} onChange={(e) => setBfMethod(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="POST">POST</MenuItem>
                    <MenuItem value="GET">GET</MenuItem>
                    <MenuItem value="PUT">PUT</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={6} md={4}>
                  <Select fullWidth size="small" value={bfMode} onChange={(e) => setBfMode(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="cluster_bomb">Cluster Bomb (all user pass combos)</MenuItem>
                    <MenuItem value="pitchfork">Pitchfork (paired user/pass lines)</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Select fullWidth size="small" value={bfPosition} onChange={(e) => setBfPosition(e.target.value)} sx={{ bgcolor: "#F5F5F7" }}>
                    <MenuItem value="body">Credentials in Body</MenuItem>
                    <MenuItem value="query">Credentials in Query</MenuItem>
                  </Select>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <TextField fullWidth size="small" label="Username field" value={bfUserParam} onChange={(e) => setBfUserParam(e.target.value)} />
                    <TextField fullWidth size="small" label="Password field" value={bfPassParam} onChange={(e) => setBfPassParam(e.target.value)} />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={6} label="Username List (one per line)" value={bfUsers} onChange={(e) => setBfUsers(e.target.value)} />
                  <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    <Typography variant="caption" sx={{ color: "#6E6E73", mr: 0.5, alignSelf: "center" }}>
                      Append preset:
                    </Typography>
                    {Object.entries(bfPresets).map(([key, preset]) => (
                      <Chip key={key} size="small" label={`+ ${preset.label} (${preset.count})`} onClick={() => appendPreset(key, setBfUsers)} sx={{ bgcolor: "#F5F5F7", fontSize: 11 }} />
                    ))}
                    {Object.keys(bfPresets).length === 0 && (
                      <Typography variant="caption" sx={{ color: "#999" }}>(presets loading...)</Typography>
                    )}
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={6} label="Password List (one per line)" value={bfPasswords} onChange={(e) => setBfPasswords(e.target.value)} />
                  <Box sx={{ mt: 1, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    <Typography variant="caption" sx={{ color: "#6E6E73", mr: 0.5, alignSelf: "center" }}>
                      Append preset:
                    </Typography>
                    {Object.entries(bfPresets).map(([key, preset]) => (
                      <Chip key={key} size="small" label={`+ ${preset.label} (${preset.count})`} onClick={() => appendPreset(key, setBfPasswords)} sx={{ bgcolor: "#F5F5F7", fontSize: 11 }} />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" label="Failure Indicator (string shown on FAILED login, e.g. 'Invalid credentials')" value={bfFailure} onChange={(e) => setBfFailure(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" label="Success Indicator (optional - takes precedence, e.g. 'Dashboard')" value={bfSuccess} onChange={(e) => setBfSuccess(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={2} label="Extra Headers (Key: Value per line)" value={bfHeaders} onChange={(e) => setBfHeaders(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField fullWidth size="small" multiline rows={2} label="Extra Body Content (merged with credentials, e.g. csrf=a1b2&remember=1)" value={bfBody} onChange={(e) => setBfBody(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap" }}>
                    <Button variant="contained" onClick={startBruteForce} disabled={bfRunning} startIcon={<SendIcon />} sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", px: 3, "&:hover": { bgcolor: "#F44336" }, "&:disabled": { bgcolor: "#E5E5E5", color: "#999" } }}>
                      {bfRunning ? "Brute Forcing..." : "Start Brute Force"}
                    </Button>
                    <Button variant="outlined" onClick={stopBruteForce} disabled={!bfRunning} sx={{ color: "#E53935", borderColor: "#E53935", borderRadius: "999px" }}>
                      Stop
                    </Button>
                    {bfStatus && (
                      <Chip
                        size="small"
                        label={`${bfStatus.completed}/${bfStatus.total_requests} attempts | ${bfStatus.matched} valid found`}
                        sx={{ bgcolor: bfRunning ? "#FFF3E0" : "#E8F5E9", color: bfRunning ? "#E65100" : "#2E7D32", fontWeight: "bold" }}
                      />
                    )}
                  </Box>
                </Grid>
              </Grid>
              {bfResults.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  {bfResults.some((r) => r.matched) && (
                    <Alert severity="error" icon={<SecurityIcon />} sx={{ mb: 2, borderRadius: 2, bgcolor: "#FFEBEE" }}>
                      <Typography variant="body2" sx={{ fontWeight: "bold", color: "#C62828" }}>
                        Valid credentials found:{" "}
                        {bfResults.filter((r) => r.matched).map((r) => {
                          const parts = String(r.payload).split(" | ");
                          return `${parts[0]}:${parts[1] ?? ""}`;
                        }).join(",  ")}
                      </Typography>
                    </Alert>
                  )}
                  <Box sx={{ maxHeight: 400, overflow: "auto", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 2 }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                      <thead>
                        <tr style={{ position: "sticky", top: 0, backgroundColor: "#F5F5F7" }}>
                          <th style={bfThStyle}>Username</th>
                          <th style={bfThStyle}>Password</th>
                          <th style={bfThStyle}>Status</th>
                          <th style={bfThStyle}>Length</th>
                          <th style={bfThStyle}>Time</th>
                          <th style={bfThStyle}>Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {bfResults.map((r, idx) => {
                          const parts = String(r.payload).split(" | ");
                          return (
                            <tr key={idx} style={{ backgroundColor: r.matched ? "#FFF8E1" : idx % 2 ? "#FAFAFA" : "#FFF" }}>
                              <td style={bfTdStyle}>{parts[0]}</td>
                              <td style={bfTdStyle}>{parts[1] ?? ""}</td>
                              <td style={bfTdStyle}>
                                <Chip size="small" label={r.status_code || "ERR"} sx={{ bgcolor: r.status_code >= 500 ? "#FFEBEE" : r.status_code >= 400 ? "#FFF3E0" : r.status_code >= 300 ? "#E3F2FD" : "#E8F5E9", fontWeight: "bold", fontSize: 11 }} />
                              </td>
                              <td style={bfTdStyle}>{r.response_length ?? 0}</td>
                              <td style={bfTdStyle}>{r.time || ""}</td>
                              <td style={bfTdStyle}>
                                {r.matched ? (
                                  <Chip size="small" label="VALID LOGIN" sx={{ bgcolor: "#2E7D32", color: "#FFF", fontWeight: "bold", fontSize: 11 }} />
                                ) : (
                                  <Typography variant="caption" sx={{ color: "#999" }}>failed</Typography>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </Box>
                </Box>
              )}
            </Box>
          )}

          {toolsTab === 3 && (
            <Box>
              {saError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setSaError("")}>
                  {saError}
                </Alert>
              )}
              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} md={9}>
                  <TextField
                    fullWidth size="small"
                    label="Website URL to fetch & analyze"
                    placeholder="https://example.com"
                    value={saUrl}
                    onChange={(e) => setSaUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && analyzeSource()}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <Button
                    variant="contained" fullWidth onClick={analyzeSource} disabled={saLoading}
                    startIcon={saLoading ? <CircularProgress size={18} color="inherit" /> : <CodeIcon />}
                    sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", py: 1, "&:hover": { bgcolor: "#F44336" }, "&:disabled": { bgcolor: "#E5E5E5", color: "#999" } }}
                  >
                    {saLoading ? "Fetching..." : "Fetch & Analyze"}
                  </Button>
                </Grid>
              </Grid>

              {!saResult && !saLoading && (
                <Typography variant="body2" sx={{ mt: 3, color: "#6E6E73" }}>
                  Enter a URL to retrieve its source code. The scanner will fingerprint technologies, search for
                  exposed secrets, sensitive comments, mixed content, missing security headers, and more.
                </Typography>
              )}

              {saResult && (
                <Box sx={{ mt: 3 }}>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                    <Chip size="small" label={`${saResult.status_code} ${saResult.reason || ""}`} sx={{ bgcolor: saResult.status_code < 400 ? "#E8F5E9" : "#FFEBEE", color: "#1D1D1F", fontWeight: "bold" }} />
                    <Chip size="small" label={`Final URL: ${saResult.final_url}`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    <Chip size="small" label={`${(saResult.total_size / 1024).toFixed(1)} KB`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    <Chip size="small" label={`${saResult.total_lines} lines`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    {saResult.elapsed != null && <Chip size="small" label={`${saResult.elapsed}s`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />}
                    {saResult.truncated && <Chip size="small" label="Source truncated to 200 KB" sx={{ bgcolor: "#FFF3E0", color: "#E65100" }} />}
                  </Box>

                  {/* Security issues found in the source */}
                  <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                    Security Analysis ({saResult.analysis.issues?.length || 0} findings)
                  </Typography>
                  {(saResult.analysis.issues?.length || 0) === 0 ? (
                    <Typography variant="body2" sx={{ color: "#2E7D32", mb: 3, fontWeight: "bold" }}>
                      No obvious security issues detected in the source code.
                    </Typography>
                  ) : (
                    <Box sx={{ mb: 3 }}>
                      {saResult.analysis.issues.map((issue, idx) => (
                        <Paper
                          key={idx}
                          sx={{ p: 1.5, mb: 1, display: "flex", alignItems: "flex-start", gap: 2, border: "1px solid rgba(0,0,0,0.08)", borderRadius: 2, bgcolor: idx % 2 ? "#FAFAFA" : "#FFF" }}
                        >
                          <Chip size="small" label={issue.severity} sx={{ bgcolor: getSeverityColor(issue.severity), color: "#FFF", fontWeight: "bold", minWidth: 72, mt: 0.25 }} />
                          <Box>
                            <Typography variant="body2" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                              {issue.title}{issue.count ? ` (${issue.count})` : ""}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "#6E6E73" }}>
                              {issue.description}
                            </Typography>
                          </Box>
                        </Paper>
                      ))}
                    </Box>
                  )}

                  {/* Detected technologies */}
                  {(saResult.analysis.technologies?.length || 0) > 0 && (
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                        Detected Technologies
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                        {saResult.analysis.technologies.map((tech) => (
                          <Chip key={tech} size="small" label={tech} sx={{ bgcolor: "#E3F2FD", color: "#1565C0", fontWeight: 600 }} />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {/* Emails & resources summary */}
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                    {(saResult.analysis.emails?.length || 0) > 0 && (
                      <Chip size="small" label={`${saResult.analysis.emails.length} email(s) found`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    )}
                    {(saResult.analysis.links?.length || 0) > 0 && (
                      <Chip size="small" label={`${saResult.analysis.links.length} link(s)`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    )}
                    {(saResult.analysis.scripts?.length || 0) > 0 && (
                      <Chip size="small" label={`${saResult.analysis.scripts.length} script(s)`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    )}
                    {(saResult.analysis.styles?.length || 0) > 0 && (
                      <Chip size="small" label={`${saResult.analysis.styles.length} stylesheet(s)`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    )}
                    {(saResult.analysis.forms?.length || 0) > 0 && (
                      <Chip size="small" label={`${saResult.analysis.forms.length} form(s)`} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F" }} />
                    )}
                  </Box>

                  {(saResult.analysis.emails?.length || 0) > 0 && (
                    <Typography variant="caption" sx={{ display: "block", color: "#6E6E73", mb: 2 }}>
                      Emails: {saResult.analysis.emails.join(", ")}
                    </Typography>
                  )}

                  {/* Source code viewer */}
                  <Button
                    variant="outlined" size="small" onClick={() => setSaShowSource(!saShowSource)}
                    startIcon={<CodeIcon />}
                    sx={{ color: "#E53935", borderColor: "#E53935", borderRadius: "999px", mb: 2 }}
                  >
                    {saShowSource ? "Hide Source Code" : "View Source Code"}
                  </Button>
                  {saShowSource && (
                    <Box sx={{ maxHeight: 480, overflow: "auto", bgcolor: "#1e1e1e", borderRadius: 2, p: 2 }}>
                      <pre style={{ margin: 0, color: "#d4d4d4", fontSize: 12, lineHeight: 1.5, fontFamily: "Consolas, 'Courier New', monospace", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                        {saResult.source || "(empty response body)"}
                      </pre>
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          )}

          {toolsTab === 4 && (
            <Box>
              {fuzzError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setFuzzError("")}>
                  {fuzzError}
                </Alert>
              )}
              <Grid container spacing={2}>
                <Grid item xs={12} md={8}>
                  <TextField fullWidth size="small" label="Target URL" placeholder="https://example.com" value={fuzzTarget} onChange={(e) => setFuzzTarget(e.target.value)} />
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField fullWidth size="small" type="number" inputProps={{ min: 1, max: 30 }} label="Max endpoints to test (max 30)" value={fuzzMaxEndpoints} onChange={(e) => setFuzzMaxEndpoints(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="body2" sx={{ color: "#6E6E73", mb: 1 }}>
                    Vulnerability tests to run on fuzz-discovered endpoints (click to toggle):
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {FUZZ_VULN_TESTS.map((t) => (
                      <Chip
                        key={t.id}
                        label={t.label}
                        onClick={() => toggleFuzzTest(t.id)}
                        sx={{
                          fontWeight: "bold",
                          cursor: "pointer",
                          bgcolor: fuzzTests.includes(t.id) ? "#E53935" : "#F5F5F7",
                          color: fuzzTests.includes(t.id) ? "#FFF" : "#6E6E73",
                        }}
                      />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <TextField fullWidth size="small" multiline rows={3} label="Custom wordlist (optional, one path per line - uses built-in 40+ paths if empty)" placeholder={"/admin\n/backup\n/config"} value={fuzzWordlist} onChange={(e) => setFuzzWordlist(e.target.value)} />
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap" }}>
                    <Button variant="contained" onClick={startFuzzer} disabled={fuzzRunning} startIcon={<SendIcon />} sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px", px: 3, "&:hover": { bgcolor: "#F44336" }, "&:disabled": { bgcolor: "#E5E5E5", color: "#999" } }}>
                      {fuzzRunning ? "Fuzzing..." : "Start Fuzz & Test"}
                    </Button>
                    {fuzzStatus && (
                      <Chip
                        size="small"
                        label={`${fuzzStatus.endpoints_discovered ?? fuzzStatus.endpoints_tested?.length ?? 0} endpoints tested | ${(fuzzStatus.vuln_findings || []).length} vulnerabilities found`}
                        sx={{ bgcolor: (fuzzStatus.vuln_findings || []).length > 0 ? "#FFEBEE" : "#E8F5E9", color: (fuzzStatus.vuln_findings || []).length > 0 ? "#C62828" : "#2E7D32", fontWeight: "bold" }}
                      />
                    )}
                  </Box>
                </Grid>
              </Grid>
              {fuzzStatus && (
                <Box sx={{ mt: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Chip
                      size="small"
                      label={fuzzStatus.status === "running" ? "Running" : fuzzStatus.status === "completed" ? "Completed" : `${fuzzStatus.status}`}
                      sx={{ bgcolor: fuzzStatus.status === "running" ? "#FFF3E0" : fuzzStatus.status === "completed" ? "#E8F5E9" : "#FFEBEE", color: "#1D1D1F", fontWeight: "bold" }}
                    />
                    <Typography variant="body2" sx={{ color: "#6E6E73" }}>
                      {fuzzStatus.phase || ""}
                    </Typography>
                  </Box>
                  {fuzzStatus.status === "running" && (
                    <LinearProgress
                      variant={fuzzStatus.progress ? "determinate" : "indeterminate"}
                      value={fuzzStatus.progress || 0}
                      sx={{ height: 6, borderRadius: 3, mb: 3, bgcolor: "#F5F5F7", "& .MuiLinearProgress-bar": { bgcolor: "#E53935" } }}
                    />
                  )}
                  {fuzzStatus.error && (
                    <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }}>
                      {fuzzStatus.error}
                    </Alert>
                  )}

                  {/* Vulnerability findings from fuzz-discovered endpoints */}
                  <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                    Vulnerabilities Found ({(fuzzStatus.vuln_findings || []).length})
                  </Typography>
                  {(fuzzStatus.vuln_findings || []).length === 0 ? (
                    <Typography variant="body2" sx={{ color: "#2E7D32", fontWeight: "bold", mb: 3 }}>
                      No vulnerabilities detected on the tested endpoints yet.
                    </Typography>
                  ) : (
                    <Box sx={{ mb: 3 }}>
                      {fuzzStatus.vuln_findings.map((f, idx) => (
                        <Paper
                          key={idx}
                          sx={{ p: 1.5, mb: 1, display: "flex", alignItems: "flex-start", gap: 2, border: f.severity === "Critical" || f.severity === "High" ? "1px solid #FFCDD2" : "1px solid rgba(0,0,0,0.08)", borderRadius: 2, bgcolor: f.severity === "Critical" || f.severity === "High" ? "#FFF8F8" : idx % 2 ? "#FAFAFA" : "#FFF" }}
                        >
                          <Chip size="small" label={f.severity || "Info"} sx={{ bgcolor: getSeverityColor(f.severity), color: "#FFF", fontWeight: "bold", minWidth: 72, mt: 0.25 }} />
                          <Box>
                            <Typography variant="body2" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                              [{f.type}] {f.title}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "#6E6E73", display: "block", wordBreak: "break-all" }}>
                              {f.url}
                            </Typography>
                            {f.fuzz_finding && (
                              <Typography variant="caption" sx={{ color: "#E65100", display: "block" }}>
                                Discovered by fuzzing: {f.fuzz_finding}
                              </Typography>
                            )}
                          </Box>
                        </Paper>
                      ))}
                    </Box>
                  )}

                  {/* Endpoints that were fuzz-discovered and tested */}
                  {(fuzzStatus.endpoints_tested || []).length > 0 && (
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                        Endpoints Tested ({fuzzStatus.endpoints_tested.length})
                      </Typography>
                      {fuzzStatus.endpoints_tested.map((ep, idx) => (
                        <Paper key={idx} sx={{ p: 1, mb: 0.5, display: "flex", alignItems: "center", gap: 2, border: "1px solid rgba(0,0,0,0.08)", borderRadius: 2, bgcolor: idx % 2 ? "#FAFAFA" : "#FFF" }}>
                          <Chip size="small" label={ep.severity || "Info"} sx={{ bgcolor: getSeverityColor(ep.severity), color: "#FFF", fontWeight: "bold", minWidth: 64 }} />
                          <Chip size="small" label={ep.status} sx={{ bgcolor: "#F5F5F7", color: "#1D1D1F", fontWeight: "bold" }} />
                          <Typography variant="body2" sx={{ color: "#1D1D1F", wordBreak: "break-all" }}>
                            {ep.url} {ep.finding ? `- ${ep.finding}` : ""}
                          </Typography>
                        </Paper>
                      ))}
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          )}
          {toolsTab === 5 && (
            <Box>
              {pdError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setPdError("")}>
                  {pdError}
                </Alert>
              )}

              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} md={8}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Target URL"
                    placeholder="https://example.com/search?q=test"
                    value={pdTarget}
                    onChange={(e) => setPdTarget(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleParameterDiscovery()}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Button
                    fullWidth
                    variant="contained"
                    onClick={handleParameterDiscovery}
                    disabled={pdLoading}
                    startIcon={pdLoading ? <CircularProgress size={16} sx={{ color: "#FFF" }} /> : <HttpIcon />}
                    sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                  >
                    {pdLoading ? "Discovering..." : "Find Parameters"}
                  </Button>
                </Grid>
              </Grid>

              {pdLoading && <LinearProgress sx={{ mt: 2, bgcolor: "#333" }} />}

              {pdResult && (
                <Box sx={{ mt: 3 }}>
                  <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
                    Found <strong>{pdResult.count}</strong> parameter(s) on{" "}
                    <strong>{pdResult.target}</strong>. Parameters marked{" "}
                    <strong>live</strong> were confirmed by the server responding
                    differently when they were supplied.
                  </Alert>

                  {pdResult.count === 0 ? (
                    <Typography variant="body1" sx={{ color: "#6E6E73" }}>
                      No parameters were discovered. Try a deeper page or provide a
                      URL that already includes a query string.
                    </Typography>
                  ) : (
                    <TableContainer
                      component={Paper}
                      sx={{ bgcolor: "#252525", border: "1px solid #444" }}
                    >
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={bfThStyle}>Parameter</TableCell>
                            <TableCell sx={bfThStyle}>Type</TableCell>
                            <TableCell sx={bfThStyle}>Location</TableCell>
                            <TableCell sx={bfThStyle}>Source</TableCell>
                            <TableCell sx={bfThStyle}>Live</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {pdResult.parameters.map((p, idx) => (
                            <TableRow key={`${p.name}-${idx}`}>
                              <TableCell sx={bfTdStyle}>
                                <Typography
                                  variant="body2"
                                  sx={{ color: "#00d4ff", fontFamily: "monospace", fontWeight: "bold" }}
                                >
                                  {p.name}
                                </Typography>
                              </TableCell>
                              <TableCell sx={bfTdStyle}>{p.type}</TableCell>
                              <TableCell sx={bfTdStyle}>
                                {(p.locations || []).join(", ")}
                              </TableCell>
                              <TableCell sx={bfTdStyle}>
                                {(p.sources || []).join(", ")}
                              </TableCell>
                              <TableCell sx={bfTdStyle}>
                                {p.live ? (
                                  <Chip
                                    size="small"
                                    label={p.live_confidence === "high" ? "live (high)" : "live (med)"}
                                    sx={{ bgcolor: "#DCFCE7", color: "#166534", fontWeight: "bold" }}
                                  />
                                ) : (
                                  <Chip
                                    size="small"
                                    label={p.live_confidence === "low" ? "no response change" : "not probed"}
                                    sx={{ bgcolor: "#F5F5F7", color: "#6E6E73" }}
                                  />
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}

                  {(pdResult.findings || []).length > 0 && (
                    <Box sx={{ mt: 3 }}>
                      <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1 }}>
                        Observations
                      </Typography>
                      {pdResult.findings.map((f, idx) => (
                        <Paper
                          key={idx}
                          sx={{
                            p: 1.5,
                            mb: 1,
                            border: "1px solid rgba(0,0,0,0.08)",
                            borderRadius: 2,
                            bgcolor: f.severity === "Medium" || f.severity === "High" ? "#FFF8F8" : "#FFF",
                          }}
                        >
                          <Chip
                            size="small"
                            label={f.severity || "Info"}
                            sx={{
                              bgcolor: getSeverityColor(f.severity),
                              color: "#FFF",
                              fontWeight: "bold",
                              mb: 0.5,
                            }}
                          />
                          <Typography variant="body2" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                            {f.title}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#6E6E73" }}>
                            {f.description}
                          </Typography>
                        </Paper>
                      ))}
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          )}
          {toolsTab === 6 && (
            <Box>
              {tfError && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setTfError("")}>
                  {tfError}
                </Alert>
              )}

              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} md={8}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Target URL"
                    placeholder="https://example.com"
                    value={tfTarget}
                    onChange={(e) => setTfTarget(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleFingerprint()}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <Button
                    fullWidth
                    variant="contained"
                    onClick={handleFingerprint}
                    disabled={tfLoading}
                    startIcon={tfLoading ? <CircularProgress size={16} sx={{ color: "#000" }} /> : <StorageIcon />}
                    sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                  >
                    {tfLoading ? "Fingerprinting..." : "Identify Architecture"}
                  </Button>
                </Grid>
              </Grid>

              {tfLoading && <LinearProgress sx={{ mt: 2, bgcolor: "#333" }} />}

              {tfResult && (
                <Box sx={{ mt: 3 }}>
                  {/* Headline answer: what is this site built on? */}
                  <Alert severity={tfResult.has_database ? "success" : "info"} sx={{ mb: 2, borderRadius: 2 }}>
                    <Typography variant="body2" sx={{ fontWeight: "bold", mb: 0.5 }}>
                      Architecture of {tfResult.target}
                    </Typography>
                    {tfResult.summary}
                  </Alert>

                  {tfResult.has_database && (
                    <Alert severity="success" icon={false} sx={{ mb: 2, borderRadius: 2, bgcolor: "#DCFCE7" }}>
                      <Typography variant="body2" sx={{ fontWeight: "bold", color: "#166534" }}>
                        Database detected:{" "}
                        {tfResult.databases
                          .map((d) => d.name + (d.version ? ` ${d.version}` : ""))
                          .join(", ")}
                      </Typography>
                    </Alert>
                  )}

                  {/* Grouped by category so the stack is easy to read */}
                  {ARCH_SECTIONS.map((section) => {
                    const items = (tfResult.architecture || {})[section.key] || [];
                    if (items.length === 0) return null;
                    return (
                      <Box key={section.key} sx={{ mb: 3 }}>
                        <Typography
                          variant="h6"
                          sx={{ fontWeight: "bold", color: "#1D1D1F", mb: 1, display: "flex", alignItems: "center", gap: 1 }}
                        >
                          {section.label}
                          <Chip size="small" label={items.length} sx={{ bgcolor: "#F5F5F7", color: "#6E6E73", fontWeight: "bold" }} />
                        </Typography>
                        {items.map((item, idx) => {
                          const conf = CONFIDENCE_COLOR[item.confidence] || CONFIDENCE_COLOR.low;
                          return (
                            <Paper
                              key={`${item.name}-${idx}`}
                              sx={{ p: 1.5, mb: 1, border: "1px solid rgba(0,0,0,0.08)", borderRadius: 2, bgcolor: idx % 2 ? "#FAFAFA" : "#FFF" }}
                            >
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                                <Typography variant="body1" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                                  {item.name}
                                </Typography>
                                {item.version && (
                                  <Chip size="small" label={item.version} sx={{ bgcolor: "#1D1D1F", color: "#FFF", fontWeight: "bold" }} />
                                )}
                                <Chip
                                  size="small"
                                  label={`${conf.label} confidence`}
                                  sx={{ bgcolor: conf.bg, color: conf.fg, fontWeight: "bold" }}
                                />
                              </Box>
                              {(item.evidence || []).length > 0 && (
                                <Typography
                                  variant="caption"
                                  sx={{ color: "#86868B", display: "block", fontFamily: "monospace", mt: 0.5, wordBreak: "break-all" }}
                                >
                                  {item.evidence.join("  |  ").slice(0, 180)}
                                </Typography>
                              )}
                            </Paper>
                          );
                        })}
                      </Box>
                    );
                  })}

                  {/* Nothing detected */}
                  {(tfResult.technologies || []).length === 0 && (
                    <Alert severity="warning" sx={{ borderRadius: 2 }}>
                      No technologies could be identified. The target may suppress
                      banners, or it may not be an HTTP service.
                    </Alert>
                  )}
                </Box>
              )}
            </Box>
          )}
          {toolsTab === 7 && (
            <Box>
              {agentError && (
                <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }} onClose={() => setAgentError("")}>
                  {agentError}
                </Alert>
              )}

              <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
                Bring your own AI key. It is held in memory for this session only,
                never written to disk, and never returned by the API.
                Disconnecting discards it immediately.
              </Alert>

              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} md={3}>
                  <Select
                    fullWidth
                    size="small"
                    value={selectedProvider}
                    onChange={(e) => {
                      setSelectedProvider(e.target.value);
                      const provider = aiProviders.find((p) => p.id === e.target.value);
                      if (provider) {
                        setSelectedModel(provider.default_model);
                        // Model names are provider-specific, so a custom name
                        // from the previous provider would be meaningless here.
                        setIsCustomModel(false);
                      }
                    }}
                    sx={{ bgcolor: "#F5F5F7" }}
                  >
                    {aiProviders.map((provider) => (
                      <MenuItem key={provider.id} value={provider.id}>
                        {provider.name}
                      </MenuItem>
                    ))}
                  </Select>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Select
                    fullWidth
                    size="small"
                    value={isCustomModel ? CUSTOM_MODEL_OPTION : selectedModel}
                    onChange={(e) => {
                      if (e.target.value === CUSTOM_MODEL_OPTION) {
                        setIsCustomModel(true);
                        setSelectedModel("");
                      } else {
                        setIsCustomModel(false);
                        setSelectedModel(e.target.value);
                      }
                    }}
                    sx={{ bgcolor: "#F5F5F7" }}
                  >
                    {(aiProviders.find((p) => p.id === selectedProvider)?.models || []).map((model) => (
                      <MenuItem key={model} value={model}>{model}</MenuItem>
                    ))}
                    <MenuItem value={CUSTOM_MODEL_OPTION}>
                      Custom model...
                    </MenuItem>
                  </Select>
                  {isCustomModel && (
                    <TextField
                      fullWidth
                      size="small"
                      label="Model name"
                      placeholder="e.g. gpt-4o-mini, llama-3.3-70b"
                      helperText="Any model your provider accepts"
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleAgentConnect()}
                      disabled={agentBusy}
                      // Mirrors MAX_MODEL_NAME_LENGTH in backend/scanner_modules/ai_agent.py
                      inputProps={{ maxLength: 200 }}
                      sx={{ mt: 1 }}
                    />
                  )}
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    size="small"
                    type="password"
                    label="API Key"
                    placeholder={agentSession ? "Session active" : "sk-..."}
                    value={agentKey}
                    onChange={(e) => setAgentKey(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAgentConnect()}
                    disabled={agentBusy}
                  />
                </Grid>
                <Grid item xs={12} md={2}>
                  <Button
                    fullWidth
                    variant="contained"
                    onClick={agentSession ? handleAgentDisconnect : handleAgentConnect}
                    disabled={agentBusy}
                    startIcon={agentSession ? <DeleteIcon /> : <AIIcon />}
                    sx={{
                      bgcolor: agentSession ? "#E53935" : "#1D1D1F",
                      color: "#FFF",
                      fontWeight: "bold",
                      "&:hover": { bgcolor: agentSession ? "#F44336" : "#000" },
                    }}
                  >
                    {agentSession ? "Disconnect" : "Connect"}
                  </Button>
                </Grid>
              </Grid>

              {agentStatus && (
                <Alert severity="success" sx={{ mt: 2, borderRadius: 2 }}>
                  {agentStatus}
                </Alert>
              )}
              {agentBusy && <LinearProgress sx={{ mt: 2, bgcolor: "#333" }} />}

              {agentSession && (
                <Box sx={{ mt: 3 }}>
                  <Tabs
                    value={agentMode}
                    onChange={(e, v) => setAgentMode(v)}
                    sx={{
                      mb: 2,
                      "& .MuiTab-root": { fontWeight: "bold", color: "#6E6E73" },
                      "& .Mui-selected": { color: "#E53935" },
                      "& .MuiTabs-indicator": { bgcolor: "#E53935" },
                    }}
                  >
                    <Tab value="ask" label="Ask" />
                    <Tab value="report" label="Generate Report" />
                    <Tab value="attack" label="Attack Plan" />
                  </Tabs>

                  {agentMode === "ask" && (
                    <Box>
                      <TextField
                        fullWidth
                        size="small"
                        label="Question about this target"
                        placeholder="Which finding should I verify first, and how?"
                        value={agentQuestion}
                        onChange={(e) => setAgentQuestion(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !e.shiftKey) {
                            e.preventDefault();
                            handleAgentRun();
                          }
                        }}
                        multiline
                        minRows={2}
                      />
                      <Button
                        variant="contained"
                        onClick={handleAgentRun}
                        disabled={agentBusy}
                        startIcon={<SendIcon />}
                        sx={{ mt: 2, bgcolor: "#1D1D1F", color: "#FFF", fontWeight: "bold" }}
                      >
                        Ask
                      </Button>

                      {agentMessages.length > 0 && (
                        <Box sx={{ mt: 3 }}>
                          {agentMessages.map((msg, idx) => (
                            <Paper
                              key={idx}
                              sx={{
                                p: 2,
                                mb: 1.5,
                                bgcolor: msg.role === "user" ? "#F5F5F7" : "#FFF",
                                border: "1px solid rgba(0,0,0,0.08)",
                                borderRadius: 2,
                              }}
                            >
                              <Typography variant="caption" sx={{ fontWeight: "bold", color: "#6E6E73" }}>
                                {msg.role === "user" ? "You" : "AI Agent"}
                              </Typography>
                              <Typography
                                variant="body2"
                                sx={{ whiteSpace: "pre-wrap", color: "#1D1D1F", mt: 0.5 }}
                              >
                                {msg.content}
                              </Typography>
                            </Paper>
                          ))}
                        </Box>
                      )}
                    </Box>
                  )}

                  {agentMode === "report" && (
                    <Box>
                      <Typography variant="body2" sx={{ color: "#6E6E73", mb: 1 }}>
                        Audience
                      </Typography>
                      <Select
                        size="small"
                        value={agentAudience}
                        onChange={(e) => setAgentAudience(e.target.value)}
                        sx={{ bgcolor: "#F5F5F7", minWidth: 240 }}
                      >
                        <MenuItem value="executive">Executive - non-technical summary</MenuItem>
                        <MenuItem value="technical">Technical - for the engineers fixing it</MenuItem>
                        <MenuItem value="full">Full - complete detailed report</MenuItem>
                      </Select>
                      <Button
                        variant="contained"
                        onClick={handleAgentRun}
                        disabled={agentBusy}
                        startIcon={<AIIcon />}
                        sx={{ mt: 2, bgcolor: "#1D1D1F", color: "#FFF", fontWeight: "bold" }}
                      >
                        Generate Report
                      </Button>
                    </Box>
                  )}

                  {agentMode === "attack" && (
                    <Box>
                      <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
                        This produces a test plan for a target you are authorised to
                        assess. It covers verification and proof-of-concept only.
                      </Alert>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={agentAuthorised}
                            onChange={(e) => setAgentAuthorised(e.target.checked)}
                          />
                        }
                        label={
                          <Typography variant="body2" sx={{ color: "#1D1D1F" }}>
                            I have written permission to test this target
                          </Typography>
                        }
                      />
                      <TextField
                        fullWidth
                        size="small"
                        label="Scope notes (optional)"
                        placeholder="e.g. staging only, no destructive tests"
                        value={agentScope}
                        onChange={(e) => setAgentScope(e.target.value)}
                        sx={{ mt: 2 }}
                      />
                      <Button
                        variant="contained"
                        onClick={handleAgentRun}
                        disabled={agentBusy || !agentAuthorised}
                        startIcon={<AIIcon />}
                        sx={{ mt: 2, bgcolor: "#1D1D1F", color: "#FFF", fontWeight: "bold" }}
                      >
                        Build Attack Plan
                      </Button>
                    </Box>
                  )}

                  {/* Report / plan output */}
                  {agentReport && (
                    <Box sx={{ mt: 3 }}>
                      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                        <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                          {agentMode === "report" ? "Generated Report" : "Attack Plan"}
                        </Typography>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={handleAgentDownload}
                          startIcon={<DownloadIcon />}
                          sx={{ color: "#E53935", borderColor: "#E53935" }}
                        >
                          Download .md
                        </Button>
                      </Box>
                      <Paper
                        sx={{
                          p: 2,
                          maxHeight: 520,
                          overflow: "auto",
                          border: "1px solid rgba(0,0,0,0.08)",
                          borderRadius: 2,
                          bgcolor: "#FAFAFA",
                        }}
                      >
                        <Typography
                          variant="body2"
                          sx={{ whiteSpace: "pre-wrap", color: "#1D1D1F", fontFamily: "monospace" }}
                        >
                          {agentReport}
                        </Typography>
                      </Paper>
                    </Box>
                  )}
                </Box>
              )}
            </Box>
          )}

        </Paper>

        {/* Scan Modules Selection Modal */}
        <Dialog
          open={modulesDialogOpen}
          onClose={() => setModulesDialogOpen(false)}
          maxWidth="md"
          fullWidth
          PaperProps={{ sx: { bgcolor: "#1e1e1e" } }}
        >
          <DialogTitle sx={{ color: "#00d4ff", borderBottom: "2px solid #00d4ff" }}>
            Select Scan Modules
          </DialogTitle>
          <DialogContent>
            <Grid container spacing={2} sx={{ mt: 1 }}>
              {SCAN_MODULES.map((module) => (
                <Grid item xs={12} sm={6} md={4} key={module.id}>
                  <Card
                    sx={{
                      bgcolor: selectedModules.includes(module.id) ? "#263545" : "#252525",
                      border: selectedModules.includes(module.id) ? "2px solid #00d4ff" : "2px solid transparent",
                      cursor: "pointer",
                      transition: "all 0.2s",
                      "&:hover": { borderColor: "#00d4ff", transform: "translateY(-2px)" },
                    }}
                    onClick={() => toggleModule(module.id)}
                  >
                    <CardContent>
                      <Typography variant="h6" sx={{ color: "#00d4ff", mb: 1 }}>
                        {selectedModules.includes(module.id) ? <CheckIcon sx={{ mr: 1, verticalAlign: "middle" }} /> : <UncheckedIcon sx={{ mr: 1, verticalAlign: "middle" }} />}
                        {module.name}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "#888" }}>
                        {module.description}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </DialogContent>
          <DialogActions sx={{ p: 3 }}>
            <Button onClick={() => setModulesDialogOpen(false)} sx={{ color: "#00d4ff" }}>
              Done
            </Button>
          </DialogActions>
        </Dialog>

        {/* Active Scans */}
        {(scanStatus === "running" || Object.keys(activeScans).length > 0) && (
          <Paper sx={{ 
            p: 4, 
            mb: 4, 
            bgcolor: "#FFF", 
            border: "1px solid rgba(0, 0, 0, 0.08)",
            borderRadius: 4,
            boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)"
          }}>
            <Typography variant="h5" gutterBottom sx={{ fontWeight: "bold", color: "#E53935", display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon /> Active Scans ({Object.keys(activeScans).length})
            </Typography>
            <List>
              {Object.entries(activeScans).map(([id, scan]) => (
                <React.Fragment key={id}>
                  <ListItem
                    secondaryAction={
                      <Chip
                        label={scan.status}
                        color={scan.status === "completed" ? "success" : "primary"}
                        size="small"
                        sx={{ fontWeight: "bold", borderRadius: "999px" }}
                      />
                    }
                  >
                    <ListItemIcon sx={{ color: "#E53935" }}>
                      <SecurityIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography sx={{ color: "#1D1D1F", fontWeight: "bold", fontSize: "16px" }}>
                          {scan.target}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography sx={{ color: "#6E6E73", fontSize: "14px" }}>
                            Started: {new Date(scan.started_at).toLocaleString()}
                          </Typography>
                          {scan.modules && (
                            <Typography sx={{ color: "#6E6E73", fontSize: "13px" }}>
                              Modules: {scan.modules.join(", ")}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                  <Divider sx={{ bgcolor: "rgba(0, 0, 0, 0.08)" }} />
                </React.Fragment>
              ))}
            </List>
          </Paper>
        )}

        {/* Scanning Progress */}
        {scanStatus === "running" && (
          <Paper sx={{ 
            p: 6, 
            mb: 4, 
            bgcolor: "#FFF", 
            border: "1px solid rgba(0, 0, 0, 0.08)",
            borderRadius: 4,
            boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)",
            textAlign: "center" 
          }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, mb: 2 }}>
              <CircularProgress sx={{ color: "#E53935" }} size={32} />
              <Typography variant="h4" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                Scanning in progress...
              </Typography>
            </Box>

            {/* Overall progress across every module in the run */}
            {(() => {
              const scan = scanId ? activeScans[scanId] : null;
              const percent = scan?.progress ?? 0;
              const done = scan?.completed_modules ?? 0;
              const total = scan?.total_modules ?? 0;
              return (
                <>
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(100, Math.max(0, percent))}
                    sx={{
                      height: 10,
                      borderRadius: 5,
                      mb: 2,
                      bgcolor: "#F5F5F7",
                      "& .MuiLinearProgress-bar": { borderRadius: 5, bgcolor: "#E53935" },
                    }}
                  />
                  <Typography variant="body1" sx={{ color: "#6E6E73", mb: 1 }}>
                    {scan?.current_step || "Preparing scan..."}
                  </Typography>
                  {total > 0 && (
                    <Typography variant="body2" sx={{ color: "#86868B" }}>
                      {done} of {total} modules complete ({percent}%)
                    </Typography>
                  )}
                </>
              );
            })()}

            {/* Per-module status chips so every scan is visible at a glance */}
            {Object.keys(allScanProgress).length > 0 && (
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center", mt: 3 }}>
                {Object.entries(allScanProgress).map(([key, mod]) => (
                  <Chip
                    key={key}
                    size="small"
                    label={
                      mod.status === "running"
                        ? `${SCAN_MODULES.find((m) => m.id === key)?.name || key} ...`
                        : mod.status === "completed"
                        ? `${SCAN_MODULES.find((m) => m.id === key)?.name || key}${mod.findings ? ` (${mod.findings})` : ""}`
                        : mod.status === "failed"
                        ? `${SCAN_MODULES.find((m) => m.id === key)?.name || key} (failed)`
                        : SCAN_MODULES.find((m) => m.id === key)?.name || key
                    }
                    sx={{
                      fontWeight: 600,
                      borderRadius: "999px",
                      bgcolor:
                        mod.status === "completed"
                          ? "#DCFCE7"
                          : mod.status === "running"
                          ? "#FEE2E2"
                          : mod.status === "failed"
                          ? "#FEF3C7"
                          : "#F5F5F7",
                      color: "#1D1D1F",
                    }}
                  />
                ))}
              </Box>
            )}

            <Box sx={{ mt: 3 }}>
              <Button
                variant="outlined"
                onClick={handleStopScan}
                startIcon={<DeleteIcon />}
                sx={{ color: "#E53935", borderColor: "#E53935", borderRadius: "999px", px: 4 }}
              >
                Stop Scan
              </Button>
            </Box>
          </Paper>
        )}


        {/* Results */}
        {results && (
          <>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={8}>
                <Paper sx={{ p: 3, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)" }}>
                  <Typography variant="h5" gutterBottom sx={{ color: "#E53935", fontWeight: "bold" }}>
                    Scan Statistics
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#F8F9FA", border: "1px solid #E5E7EB", boxShadow: "0 4px 16px rgba(0,0,0,0.06)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(0,0,0,0.1)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#1D1D1F", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.total_findings ?? results.findings?.length ?? 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#6E6E73", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            Total
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#FEF2F2", border: "1px solid #FECACA", boxShadow: "0 4px 16px rgba(220,53,69,0.12)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(220,53,69,0.18)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#dc2626", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.critical || 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#B91C1C", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            Critical
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#FFF7ED", border: "1px solid #FED7AA", boxShadow: "0 4px 16px rgba(253,126,20,0.12)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(253,126,20,0.18)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#ea580c", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.high || 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#C2410C", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            High
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#FFFBEB", border: "1px solid #FDE68A", boxShadow: "0 4px 16px rgba(255,193,7,0.16)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(255,193,7,0.22)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#d97706", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.medium || 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#B45309", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            Medium
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#F0F9FF", border: "1px solid #BAE6FD", boxShadow: "0 4px 16px rgba(23,162,184,0.14)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(23,162,184,0.2)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#0e7490", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.low || 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#0e7490", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            Low
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ bgcolor: "#F8F9FA", border: "1px solid #D1D5DB", boxShadow: "0 4px 16px rgba(100,116,139,0.12)", borderRadius: 3, transition: "transform 250ms cubic-bezier(0.4,0,0.2,1)", "&:hover": { transform: "translateY(-2px)", boxShadow: "0 8px 24px rgba(100,116,139,0.18)" } }}>
                        <CardContent sx={{ textAlign: "center", py: 3 }}>
                          <Typography variant="h3" sx={{ color: "#64748b", fontWeight: 800, lineHeight: 1.1 }}>
                            {results.statistics?.info || 0}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#475569", fontWeight: "bold", letterSpacing: "0.5px" }}>
                            Info
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>
              
              <Grid item xs={12}>
                <Grid container spacing={3} alignItems="stretch">
                  {/* Severity Donut Chart */}
                  <Grid item xs={12} md={5}>
                    <Paper sx={{ p: 3, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)", height: "100%" }}>
                      <Typography variant="h6" gutterBottom sx={{ color: "#E53935", fontWeight: "bold" }}>
                        Severity Distribution
                      </Typography>
                      {chartData.length > 0 && chartData.some((d) => d.value > 0) ? (
                        <ResponsiveContainer width="100%" height={280}>
                          <PieChart>
                            <Pie
                              data={chartData}
                              cx="50%"
                              cy="50%"
                              labelLine={false}
                              label={(entry) => `${entry.name}: ${entry.value}`}
                              outerRadius={90}
                              innerRadius={55}
                              fill="#8884d8"
                              dataKey="value"
                            >
                              {chartData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: "#FFFFFF", border: "1px solid rgba(0,0,0,0.1)", borderRadius: 10, color: "#1D1D1F", boxShadow: "0 8px 24px rgba(0,0,0,0.12)" }} itemStyle={{ color: "#1D1D1F" }} labelStyle={{ color: "#1D1D1F", fontWeight: 700 }} />
                            <Legend layout="horizontal" verticalAlign="bottom" height={38} iconSize={10} wrapperStyle={{ color: "#6E6E73", fontSize: "12px", paddingTop: 8 }} />
                          </PieChart>
                        </ResponsiveContainer>
                      ) : (
                        <Typography sx={{ color: "#86868B", textAlign: "center", mt: 4 }}>
                          No findings to display
                        </Typography>
                      )}
                    </Paper>
                  </Grid>

                  {/* Risk Score */}
                  <Grid item xs={12} md={3}>
                    <Paper sx={{ p: 3, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)", height: "100%" }}>
                      <Typography variant="h6" gutterBottom sx={{ color: "#E53935", fontWeight: "bold" }}>
                        Risk Score
                      </Typography>
                      <Box sx={{ textAlign: "center", mt: 2 }}>
                        <Box sx={{ display: "flex", alignItems: "baseline", justifyContent: "center", gap: 1 }}>
                          <Typography variant="h2" sx={{ color: riskScore.color, fontWeight: "bold", fontSize: "48px", m: 0 }}>
                            {riskScore.score}
                          </Typography>
                          <Typography variant="body2" sx={{ color: "#888", mb: 1 }}>
                            / 100
                          </Typography>
                        </Box>
                        <Chip
                          label={riskScore.level}
                          size="small"
                          sx={{
                            bgcolor: riskScore.color,
                            color: "white",
                            fontWeight: "bold",
                            mt: 2,
                          }}
                        />
                        <Typography variant="body2" sx={{ color: "#888", mt: 2, display: "block" }}>
                          {riskScore.level === "None"
                            ? "No vulnerabilities detected"
                            : `Overall risk based on ${results.findings.length} findings`}
                        </Typography>
                      </Box>
                    </Paper>
                  </Grid>

                  {/* Findings by Severity (Bar Chart) */}
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 3, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)", height: "100%" }}>
                      <Typography variant="h6" gutterBottom sx={{ color: "#E53935", fontWeight: "bold" }}>
                        Findings by Severity
                      </Typography>
                      {chartData.some((d) => d.value > 0) ? (
                        <ResponsiveContainer width="100%" height={260}>
                          <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 20, left: 80, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.08)" />
                            <XAxis type="number" stroke="#6E6E73" tick={{ fill: "#6E6E73", fontSize: 12 }} />
                            <YAxis dataKey="name" type="category" stroke="#6E6E73" tick={{ fill: "#1D1D1F", fontSize: 12, fontWeight: 600 }} width={80} />
                            <Tooltip contentStyle={{ backgroundColor: "#FFFFFF", border: "1px solid rgba(0,0,0,0.1)", borderRadius: 10, color: "#1D1D1F", boxShadow: "0 8px 24px rgba(0,0,0,0.12)" }} itemStyle={{ color: "#1D1D1F" }} labelStyle={{ color: "#1D1D1F", fontWeight: 700 }} cursor={{ fill: "rgba(0,0,0,0.04)" }} />
                            <Bar dataKey="value" name="Findings" radius={[0, 4, 4, 0]}>
                              {chartData.map((entry, index) => (
                                <Cell key={`sev-bar-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <Typography sx={{ color: "#86868B", textAlign: "center", mt: 4 }}>
                          No findings to display
                        </Typography>
                      )}
                    </Paper>
                  </Grid>
                </Grid>
              </Grid>

              {/* Vulnerability Type Breakdown (Bar Chart) */}
              <Grid item xs={12} sx={{ mt: 3 }}>
                <Paper sx={{ p: 3, bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)" }}>
                  <Typography variant="h6" gutterBottom sx={{ color: "#E53935", fontWeight: "bold" }}>
                    Findings by Vulnerability Type
                  </Typography>
                  {typeData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={320}>
                      <BarChart data={typeData} margin={{ top: 5, right: 20, left: 0, bottom: 40 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.08)" vertical={false} />
                        <XAxis
                          dataKey="name"
                          stroke="#6E6E73"
                          tick={{ fontSize: 11, fill: "#6E6E73" }}
                          angle={-45}
                          textAnchor="end"
                          height={60}
                        />
                        <YAxis stroke="#6E6E73" tick={{ fill: "#6E6E73", fontSize: 12 }} />
                        <Tooltip contentStyle={{ backgroundColor: "#FFFFFF", border: "1px solid rgba(0,0,0,0.1)", borderRadius: 10, color: "#1D1D1F", boxShadow: "0 8px 24px rgba(0,0,0,0.12)" }} itemStyle={{ color: "#1D1D1F" }} labelStyle={{ color: "#1D1D1F", fontWeight: 700 }} cursor={{ fill: "rgba(0,0,0,0.04)" }} />
                        <Legend wrapperStyle={{ color: "#6E6E73", fontSize: "12px", paddingTop: 8 }} />
                        <Bar dataKey="count" name="Findings Count" radius={[4, 4, 0, 0]}>
                          {typeData.map((entry, index) => (
                            <Cell key={`type-bar-${index}`} fill={getSeverityColor(entry.highestSeverity)} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <Typography sx={{ color: "#888", textAlign: "center", mt: 4 }}>
                      No findings to display
                    </Typography>
                  )}
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)", overflow: "hidden" }}>
              <Box sx={{ borderBottom: 1, borderColor: "rgba(0, 0, 0, 0.08)", display: "flex", justifyContent: "space-between", alignItems: "center", p: 1, pl: 2, flexWrap: "wrap", gap: 1 }}>
                <Tabs
                  value={selectedTab}
                  onChange={(e, v) => setSelectedTab(v)}
                  sx={{
                    "& .MuiTab-root": { color: "#6E6E73", fontWeight: "bold" },
                    "& .Mui-selected": { color: "#E53935" },
                    "& .MuiTabs-indicator": { bgcolor: "#E53935" },
                  }}
                >
                  <Tab label={`Findings (${results.findings?.length || 0})`} />
                  <Tab label="Scan Details" />
                  <Tab label="Open Ports" />
                  <Tab label="Rate Limits" />
                  <Tab label="Encoder/Decoder" />
                </Tabs>
                <Box sx={{ display: "flex", gap: 1, mr: 2, flexWrap: "wrap" }}>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<AIIcon />}
                    onClick={runAIAnalysis}
                    sx={{ color: "#E53935", borderColor: "rgba(229, 57, 53, 0.5)", "&:hover": { borderColor: "#E53935", bgcolor: "rgba(229, 57, 53, 0.06)" } }}
                  >
                    AI Analyze
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<ChatIcon />}
                    onClick={openAIChat}
                    sx={{ color: "#1D1D1F", borderColor: "rgba(0,0,0,0.2)", "&:hover": { borderColor: "#1D1D1F", bgcolor: "rgba(0,0,0,0.04)" } }}
                  >
                    AI Chat
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<DownloadIcon />}
                    onClick={downloadReport}
                    sx={{ color: "#1D1D1F", borderColor: "rgba(0,0,0,0.2)", "&:hover": { borderColor: "#1D1D1F", bgcolor: "rgba(0,0,0,0.04)" } }}
                  >
                    Report
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<OpenInNewIcon />}
                    onClick={openResultsWindow}
                    sx={{ color: "#1D1D1F", borderColor: "rgba(0,0,0,0.2)", "&:hover": { borderColor: "#1D1D1F", bgcolor: "rgba(0,0,0,0.04)" } }}
                  >
                    Results Window
                  </Button>
                </Box>
              </Box>

              <TabPanel value={selectedTab} index={0}>
                <List sx={{ bgcolor: "transparent", p: 2 }}>
                  {results.findings?.length === 0 ? (
                    <Alert
                      severity="success"
                      icon={<CheckIcon sx={{ color: "#16a34a" }} />}
                      sx={{ borderRadius: 3, bgcolor: "rgba(22, 163, 74, 0.08)", color: "#166534", border: "1px solid rgba(22, 163, 74, 0.25)" }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: "bold" }}>
                        No vulnerabilities found
                      </Typography>
                      <Typography variant="body2">
                        The scan completed without detecting any issues in the modules that ran.
                        Review the Scan Details tab for target information.
                      </Typography>
                    </Alert>
                  ) : (
                    results.findings?.map((finding, index) => {
                      const isExpanded = !!expandedFindings[index];
                      const severityColor = getSeverityColor(finding.severity);
                      return (
                        <Paper
                          key={index}
                          sx={{
                            mb: 2,
                            bgcolor: "#252525",
                            borderLeft: `5px solid ${severityColor}`,
                            cursor: "pointer",
                            transition: "all 0.2s",
                            "&:hover": { transform: "translateX(5px)", boxShadow: "0 4px 12px rgba(0,0,0,0.3)" },
                          }}
                          onClick={() =>
                            setExpandedFindings((prev) => ({
                              ...prev,
                              [index]: !prev[index],
                            }))
                          }
                        >
                          <ListItem>
                            <ListItemIcon sx={{ color: severityColor }}>
                              {getTypeIcon(finding.type)}
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                                  <Typography variant="h6" sx={{ color: "#00d4ff", fontWeight: "bold" }}>
                                    {finding.title}
                                  </Typography>
                                  <Box sx={{ display: "flex", gap: 0.5 }}>
                                    <Chip
                                      label={finding.type}
                                      size="small"
                                      sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                                    />
                                    <Chip
                                      label={finding.severity}
                                      size="small"
                                      sx={{
                                        bgcolor: severityColor,
                                        color: "white",
                                        fontWeight: "bold",
                                      }}
                                    />
                                    {finding.merged_count > 0 && (
                                      <Chip
                                        label={`${finding.merged_count + 1} merged`}
                                        size="small"
                                        title="Duplicate reports of this issue were merged"
                                        sx={{
                                          bgcolor: "#4a4a4a",
                                          color: "#e0e0e0",
                                          fontWeight: "bold",
                                        }}
                                      />
                                    )}
                                  </Box>
                                </Box>
                              }
                              secondary={
                                <Typography sx={{ color: "#b0b0b0", mt: 1 }}>
                                  {finding.description}
                                </Typography>
                              }
                            />
                            {isExpanded ? <ExpandLessIcon sx={{ color: "#00d4ff" }} /> : <ExpandMoreIcon sx={{ color: "#888" }} />}
                          </ListItem>
                          {isExpanded && (
                            <Box sx={{ px: 3, pb: 2 }}>
                              <Divider sx={{ bgcolor: "#444", mb: 2 }} />
                              <Grid container spacing={2}>
                                <Grid item xs={12}>
                                  <Typography variant="body2" sx={{ color: "#888" }}>
                                    <strong style={{ color: "#00d4ff" }}>URL:</strong>{" "}
                                    <code style={{ color: "#00ff00", backgroundColor: "#1e1e1e", padding: "2px 6px", borderRadius: "4px" }}>
                                      {finding.url || "N/A"}
                                    </code>
                                    <CopyButton text={finding.url} label="Copy URL" />
                                  </Typography>
                                </Grid>
                                {finding.payload && (
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ color: "#888" }}>
                                      <strong style={{ color: "#00d4ff" }}>Payload:</strong>{" "}
                                      <code style={{ color: "#ff6b6b", backgroundColor: "#1e1e1e", padding: "2px 6px", borderRadius: "4px" }}>
                                        {finding.payload}
                                      </code>
                                      <CopyButton text={finding.payload} label="Copy Payload" />
                                    </Typography>
                                  </Grid>
                                )}
                                {finding.payloads && finding.payloads.length > 1 && (
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ color: "#888" }}>
                                      <strong style={{ color: "#00d4ff" }}>
                                        Payloads that confirmed this ({finding.payloads.length}):
                                      </strong>
                                    </Typography>
                                    {finding.payloads.map((p, i) => (
                                      <Typography key={i} variant="body2" sx={{ mt: 0.5 }}>
                                        <code
                                          style={{
                                            color: "#ff6b6b",
                                            backgroundColor: "#1e1e1e",
                                            padding: "2px 6px",
                                            borderRadius: "4px",
                                            wordBreak: "break-all",
                                          }}
                                        >
                                          {p}
                                        </code>
                                      </Typography>
                                    ))}
                                  </Grid>
                                )}
                                {finding.modules && finding.modules.length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ color: "#888" }}>
                                      <strong style={{ color: "#00d4ff" }}>Reported by:</strong>{" "}
                                      <span style={{ color: "#e0e0e0" }}>
                                        {finding.modules.join(", ")}
                                      </span>
                                    </Typography>
                                  </Grid>
                                )}
                                {finding.evidence_list && finding.evidence_list.length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ color: "#888" }}>
                                      <strong style={{ color: "#00d4ff" }}>Evidence:</strong>
                                    </Typography>
                                    {finding.evidence_list.map((e, i) => (
                                      <Typography key={i} variant="body2" sx={{ color: "#e0e0e0" }}>
                                        {e}
                                      </Typography>
                                    ))}
                                  </Grid>
                                )}
                                {finding.variants && finding.variants.length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ color: "#888" }}>
                                      <strong style={{ color: "#00d4ff" }}>
                                        Also detected as:
                                      </strong>
                                    </Typography>
                                    {finding.variants.map((v, i) => (
                                      <Typography key={i} variant="body2" sx={{ color: "#e0e0e0" }}>
                                        {v}
                                      </Typography>
                                    ))}
                                  </Grid>
                                )}
                                <Grid item xs={12}>
                                  <Typography variant="body2" sx={{ color: "#888" }}>
                                    <strong style={{ color: "#00d4ff" }}>Remediation:</strong>{" "}
                                    <span style={{ color: "#e0e0e0" }}>{finding.remediation}</span>
                                  </Typography>
                                </Grid>
                                {finding.poc && (
                                  <Grid item xs={12}>
                                    <PocBlock poc={finding.poc} />
                                  </Grid>
                                )}
                              </Grid>
                            </Box>
                          )}
                        </Paper>
                      );
                    })
                  )}
                </List>
              </TabPanel>

              <TabPanel value={selectedTab} index={1}>
                <Box sx={{ bgcolor: "#1e1e1e", p: 2, borderRadius: 2 }}>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>Target:</strong> {results.target}
                  </Typography>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>Domain:</strong> {results.domain}
                  </Typography>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>IP Address:</strong>{" "}
                    <code style={{ color: "#00ff00" }}>{results.ip_address}</code>
                  </Typography>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>Scan Type:</strong>{" "}
                    <Chip
                      label={results.is_ip ? "IP Scan" : "URL Scan"}
                      size="small"
                      sx={{ bgcolor: results.is_ip ? "#fd7e14" : "#00d4ff", color: "#000" }}
                    />
                  </Typography>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>Firewall:</strong>{" "}
                    <Chip
                      label={results.firewall || "None"}
                      size="small"
                      sx={{
                        bgcolor: results.firewall ? "#ffc107" : "#28a745",
                        color: results.firewall ? "#000" : "white",
                      }}
                    />
                  </Typography>
                  <Typography variant="body1" sx={{ color: "#e0e0e0", mb: 1 }}>
                    <strong style={{ color: "#00d4ff" }}>Technologies:</strong>
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mt: 1 }}>
                    {results.technologies?.map((tech, i) => (
                      <Chip
                        key={i}
                        label={tech}
                        size="small"
                        sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                      />
                    ))}
                  </Box>
                </Box>
              </TabPanel>

              <TabPanel value={selectedTab} index={2}>
                {results.open_ports?.length > 0 ? (
                  <List sx={{ bgcolor: "#1e1e1e", p: 2 }}>
                    {results.open_ports.map((port, i) => (
                      <ListItem key={i} sx={{ borderBottom: "1px solid #333" }}>
                        <ListItemIcon sx={{ color: "#00d4ff" }}>
                          <NetworkIcon />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography sx={{ color: "#fff", fontWeight: "bold" }}>
                              Port {port.port} ({port.service})
                            </Typography>
                          }
                          secondary={
                            <Typography sx={{ color: "#888" }}>
                              Status: {port.status}
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                ) : (
                  <Alert severity="info" sx={{ bgcolor: "#252525", color: "#888" }}>
                    No open ports detected or scan limited to web ports.
                  </Alert>
                )}
              </TabPanel>

              <TabPanel value={selectedTab} index={3}>
                <Box sx={{ bgcolor: "#1e1e1e", p: 2, borderRadius: 2 }}>
                  <Typography variant="body2" sx={{ color: "#e0e0e0", fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(results.rate_limits || {}, null, 2)}
                  </Typography>
                </Box>
              </TabPanel>

              <TabPanel value={selectedTab} index={4}>
                <Box sx={{ bgcolor: "#1e1e1e", p: 3, borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#00d4ff", mb: 2 }}>
                    Encoder / Decoder Tool
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#888", mb: 3 }}>
                    Encode or decode payloads using various encoding schemes for WAF bypass and security testing.
                  </Typography>

                  <Grid container spacing={3}>
                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Payload"
                        value={edPayload}
                        onChange={(e) => setEdPayload(e.target.value)}
                        placeholder="Enter payload to encode or decode..."
                        multiline
                        rows={3}
                        sx={{
                          "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                          "& .MuiInputLabel-root": { color: "#888" },
                        }}
                      />
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <FormControl fullWidth>
                        <InputLabel sx={{ color: "#888" }}>Encoding Type</InputLabel>
                        <Select
                          value={edEncodingType}
                          label="Encoding Type"
                          onChange={(e) => setEdEncodingType(e.target.value)}
                          sx={{
                            "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                            "& .MuiInputLabel-root": { color: "#888" },
                          }}
                        >
                          {edAvailableEncodings.encodings?.map((enc) => (
                            <MenuItem key={enc} value={enc}>
                              {enc}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <FormControl fullWidth>
                        <InputLabel sx={{ color: "#888" }}>Decoding Type</InputLabel>
                        <Select
                          value={edDecodingType}
                          label="Decoding Type"
                          onChange={(e) => setEdDecodingType(e.target.value)}
                          sx={{
                            "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                            "& .MuiInputLabel-root": { color: "#888" },
                          }}
                        >
                          {edAvailableEncodings.decodings?.map((dec) => (
                            <MenuItem key={dec} value={dec}>
                              {dec}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Grid>

                    <Grid item xs={12}>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                        <Button
                          variant="contained"
                          onClick={handleEncode}
                          disabled={edLoading}
                          sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                        >
                          Encode
                        </Button>
                        <Button
                          variant="contained"
                          onClick={handleDecode}
                          disabled={edLoading}
                          sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                        >
                          Decode
                        </Button>
                        <Button
                          variant="outlined"
                          onClick={handleSmartDecode}
                          disabled={edLoading}
                          sx={{ color: "#00d4ff", borderColor: "#00d4ff" }}
                        >
                          Smart Decode
                        </Button>
                        <Button
                          variant="outlined"
                          onClick={handleBruteDecode}
                          disabled={edLoading}
                          sx={{ color: "#00d4ff", borderColor: "#00d4ff" }}
                        >
                          Brute Force
                        </Button>
                        <Button
                          variant="outlined"
                          onClick={handleDetect}
                          disabled={edLoading}
                          sx={{ color: "#00d4ff", borderColor: "#00d4ff" }}
                        >
                          Auto-Detect
                        </Button>
                      </Box>
                    </Grid>

                    {edLoading && (
                      <Grid item xs={12}>
                        <LinearProgress sx={{ bgcolor: "#333" }} />
                      </Grid>
                    )}

                    {edError && (
                      <Grid item xs={12}>
                        <Alert severity="error" sx={{ bgcolor: "#252525", color: "#ff5555" }}>
                          {edError}
                        </Alert>
                      </Grid>
                    )}

                    {edResult && (
                      <Grid item xs={12}>
                        <Paper sx={{ bgcolor: "#252525", p: 2, border: "1px solid #00d4ff" }}>
                          <Typography variant="subtitle2" sx={{ color: "#00d4ff", mb: 1 }}>
                            Result:
                          </Typography>
                          <Typography
                            variant="body2"
                            sx={{
                              color: "#e0e0e0",
                              fontFamily: "monospace",
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-all",
                            }}
                          >
                            {edResult}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}

                    {edBruteResults && Object.keys(edBruteResults).length > 0 && (
                      <Grid item xs={12}>
                        <Paper sx={{ bgcolor: "#252525", p: 2, border: "1px solid #ff9800" }}>
                          <Typography variant="subtitle2" sx={{ color: "#ff9800", mb: 2 }}>
                            Brute Force Results:
                          </Typography>
                          {Object.entries(edBruteResults).map(([method, result]) => (
                            <Box key={method} sx={{ mb: 2 }}>
                              <Typography variant="caption" sx={{ color: "#00d4ff", fontWeight: "bold" }}>
                                {method}:
                              </Typography>
                              <Typography
                                variant="body2"
                                sx={{
                                  color: "#e0e0e0",
                                  fontFamily: "monospace",
                                  whiteSpace: "pre-wrap",
                                  wordBreak: "break-all",
                                }}
                              >
                                {result}
                              </Typography>
                            </Box>
                          ))}
                        </Paper>
                      </Grid>
                    )}
                  </Grid>
                </Box>
              </TabPanel>
             </Paper>
          </>
        )}
      </Box>

      {/* AI Chat Dialog */}
      <Dialog
        open={aiDialogOpen}
        onClose={() => setAiDialogOpen(false)}
        maxWidth="md"
        fullWidth
        PaperProps={{ sx: { bgcolor: "#1e1e1e", height: "80vh" } }}
      >
        <DialogTitle sx={{ color: "#00d4ff", borderBottom: "2px solid #00d4ff", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AIIcon /> AI Security Assistant
          </Box>
          <IconButton onClick={() => setAiDialogOpen(false)} sx={{ color: "#fff" }}>
            <DeleteIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", p: 0 }}>
          <Box sx={{ p: 2, borderBottom: "1px solid #333" }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "#888" }}>AI Provider</InputLabel>
                  <Select
                    value={selectedProvider}
                    label="AI Provider"
                    onChange={(e) => {
                      setSelectedProvider(e.target.value);
                      const provider = aiProviders.find(p => p.id === e.target.value);
                      if (provider) {
                        setSelectedModel(provider.default_model);
                        // Custom names belong to the previous provider only.
                        setIsCustomModel(false);
                      }
                    }}
                    sx={{
                      "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                      "& .MuiInputLabel-root": { color: "#888" },
                    }}
                  >
                    {aiProviders.map((provider) => (
                      <MenuItem key={provider.id} value={provider.id}>
                        {provider.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "#888" }}>Model</InputLabel>
                  <Select
                    value={isCustomModel ? CUSTOM_MODEL_OPTION : selectedModel}
                    label="Model"
                    onChange={(e) => {
                      if (e.target.value === CUSTOM_MODEL_OPTION) {
                        setIsCustomModel(true);
                        setSelectedModel("");
                      } else {
                        setIsCustomModel(false);
                        setSelectedModel(e.target.value);
                      }
                    }}
                    sx={{
                      "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                      "& .MuiInputLabel-root": { color: "#888" },
                    }}
                  >
                    {aiProviders.find(p => p.id === selectedProvider)?.models.map((model) => (
                      <MenuItem key={model} value={model}>
                        {model}
                      </MenuItem>
                    )) || <MenuItem value={selectedModel}>{selectedModel}</MenuItem>}
                    <MenuItem value={CUSTOM_MODEL_OPTION}>
                      Custom model...
                    </MenuItem>
                  </Select>
                </FormControl>
                {isCustomModel && (
                  <TextField
                    fullWidth
                    size="small"
                    label="Model name"
                    placeholder="e.g. gpt-4o-mini, llama-3.3-70b"
                    helperText="Any model your provider accepts"
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    // Mirrors MAX_MODEL_NAME_LENGTH in backend/scanner_modules/ai_agent.py
                    inputProps={{ maxLength: 200 }}
                    sx={{
                      mt: 1,
                      "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                      "& .MuiInputLabel-root": { color: "#888" },
                    }}
                  />
                )}
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  size="small"
                  label="API Key"
                  type="password"
                  value={aiApiKey}
                  onChange={(e) => setAiApiKey(e.target.value)}
                  sx={{
                    "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                    "& .MuiInputLabel-root": { color: "#888" },
                  }}
                  placeholder="sk-..."
                />
              </Grid>
            </Grid>
          </Box>
          <Box sx={{ flex: 1, overflow: "auto", p: 2, maxHeight: "50vh" }}>
            {aiMessages.length === 0 && (
              <Alert severity="info" sx={{ bgcolor: "#252525", color: "#888", mb: 2 }}>
                Select your AI provider (OpenAI, Claude, Gemini, Mistral, Cohere), enter your API key, and start chatting! You can ask questions about vulnerabilities, request remediation help, or analyze scan results.
              </Alert>
            )}
            {aiMessages.map((msg, i) => (
              <Box
                key={i}
                sx={{
                  mb: 2,
                  p: 2,
                  borderRadius: 2,
                  bgcolor: msg.role === "user" ? "#263545" : "#252525",
                  border: msg.role === "user" ? "1px solid #00d4ff" : "1px solid #444",
                  ml: msg.role === "user" ? "20%" : 0,
                  mr: msg.role === "assistant" ? "20%" : 0,
                }}
              >
                <Typography variant="body2" sx={{ color: "#888", mb: 0.5, fontWeight: "bold" }}>
                  {msg.role === "user" ? "You" : (selectedProvider ? (aiProviders.find(p => p.id === selectedProvider)?.name || 'AI') : 'Red Dragon AI')}
                </Typography>
                <Typography variant="body1" sx={{ color: "#e0e0e0", whiteSpace: "pre-wrap" }}>
                  {msg.content}
                </Typography>
              </Box>
            ))}
            {aiLoading && (
              <Box sx={{ textAlign: "center", mt: 2 }}>
                <CircularProgress size={24} sx={{ color: "#00d4ff" }} />
                <Typography sx={{ color: "#888", mt: 1 }}>AI is thinking...</Typography>
              </Box>
            )}
          </Box>
          <Box sx={{ p: 2, borderTop: "1px solid #333", display: "flex", gap: 1 }}>
            <TextField
              fullWidth
              size="small"
              label="Ask AI anything..."
              value={aiInput}
              onChange={(e) => setAiInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  sendAIMessage();
                }
              }}
              sx={{
                "& .MuiInputBase-root": { bgcolor: "#252525", color: "white" },
                "& .MuiInputLabel-root": { color: "#888" },
              }}
            />
            <Button
              variant="contained"
              onClick={sendAIMessage}
              disabled={aiLoading || !aiInput.trim()}
              startIcon={<SendIcon />}
              sx={{ bgcolor: "#00d4ff", color: "#000", "&:hover": { bgcolor: "#00b8e6" } }}
            >
              Send
            </Button>
          </Box>
        </DialogContent>
      </Dialog>

      {/* Toast notification */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((prev) => ({ ...prev, open: false }))}
        sx={{ "& .MuiAlert-root": { borderRadius: 2, fontWeight: 600 } }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((prev) => ({ ...prev, open: false }))}
          sx={{
            width: "100%",
            bgcolor: snackbar.severity === "error"
              ? (themeMode === "dark" ? "#581c1c" : "#ffebee")
              : snackbar.severity === "success"
                ? (themeMode === "dark" ? "#1d3a24" : "#e8f5e9")
                : snackbar.severity === "warning"
                  ? (themeMode === "dark" ? "#5d3f0a" : "#fff3e0")
                  : (themeMode === "dark" ? "#1d2d3a" : "#e3f2fd"),
            color: snackbar.severity === "error"
              ? (themeMode === "dark" ? "#ff6f61" : "#c62828")
              : snackbar.severity === "success"
                ? (themeMode === "dark" ? "#2e7d32" : "#2e7d32")
                : snackbar.severity === "warning"
                  ? (themeMode === "dark" ? "#ffb74d" : "#ef6c00")
                  : (themeMode === "dark" ? "#00d4ff" : "#1565c0"),
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default App;





