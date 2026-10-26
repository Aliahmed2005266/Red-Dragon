import React, { useEffect, useState } from "react";
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Paper,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  LinearProgress,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Button,
} from "@mui/material";
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  ExpandLess as ExpandLessIcon,
  ExpandMore as ExpandMoreIcon,
  Download as DownloadIcon,
  CheckCircle as CheckIcon,
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
// Importing from App also applies the launch-token header to axios (its module
// body runs on import), so the API calls below are authenticated the same way
// as in the main window.
import { COLORS, PocBlock, CopyButton, getSeverityColor, getTypeIcon } from "./App";

/**
 * The results-only window.
 *
 * Opened by the desktop shell (or as a tab via ?view=results&scanId=...), it
 * shows nothing but one scan's outcome: progress while the scan runs, then the
 * statistics, charts and the full findings list. All data comes from the same
 * backend endpoints the main window uses, keyed by the scan id in the URL.
 */
export default function ResultsWindow({ themeMode = "light" }) {
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("scanId") || "";

  const [status, setStatus] = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    if (!scanId) {
      setError("No scan id was provided to this window.");
      return undefined;
    }

    let cancelled = false;

    const fetchResults = async () => {
      try {
        const response = await axios.get(`/api/scan/${scanId}/results`);
        if (!cancelled) setResults(response.data);
      } catch (err) {
        if (!cancelled) {
          console.error(`Failed to fetch results for scan ${scanId}:`, err);
        }
      }
    };

    const checkStatus = async () => {
      try {
        const response = await axios.get(`/api/scan/${scanId}/status`);
        if (cancelled) return;
        setStatus(response.data);

        if (
          response.data.status === "completed" ||
          response.data.status === "cancelled"
        ) {
          await fetchResults();
        } else if (response.data.status === "error") {
          setError(response.data.error || "Scan failed");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.response?.data?.error || "Failed to check the scan status");
        }
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 2000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId]);

  const downloadReport = async () => {
    try {
      const response = await axios.get(`/api/scan/${scanId}/report`);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `red_dragon_report_${scanId}.html`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      link.remove();
    } catch (err) {
      setError("Failed to download report");
    }
  };

  const chartData = (() => {
    if (!results || !results.findings) return [];
    const data = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    results.findings.forEach((f) => {
      const severity = f.severity || "Info";
      if (severity in data) data[severity] += 1;
    });
    return Object.entries(data).map(([name, value]) => ({ name, value }));
  })();

  const riskScore = (() => {
    if (!results || !results.findings || results.findings.length === 0) {
      return { score: 0, level: "None", color: "#16a34a" };
    }
    const sevWeight = { Critical: 100, High: 75, Medium: 50, Low: 25, Info: 10 };
    let total = 0;
    results.findings.forEach((f) => {
      total += sevWeight[f.severity] || 10;
    });
    const score = Math.min(100, Math.round(total / results.findings.length));
    const level =
      score >= 80 ? "Critical" :
      score >= 60 ? "High" :
      score >= 40 ? "Medium" :
      score > 0 ? "Low" : "None";
    return { score, level, color: getSeverityColor(level) };
  })();

  const running = status && status.status === "running";

  return (
    <Box sx={{ flexGrow: 1, bgcolor: "#FFFFFF", minHeight: "100vh" }}>
      <AppBar
        position="sticky"
        sx={{
          bgcolor: "rgba(255, 255, 255, 0.72)",
          backdropFilter: "blur(20px) saturate(180%)",
          WebkitBackdropFilter: "blur(20px) saturate(180%)",
          boxShadow: "none",
          borderBottom: "1px solid rgba(0, 0, 0, 0.08)",
        }}
      >
        <Toolbar>
          <SecurityIcon sx={{ mr: 1.5, fontSize: 32, color: "#E53935" }} />
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
            RED DRAGON - RESULTS
          </Typography>
          {status?.target && (
            <Chip
              size="small"
              icon={<BugIcon sx={{ fontSize: 16, color: "#FFF !important" }} />}
              label={status.target}
              sx={{
                bgcolor: "#E53935",
                color: "#FFF",
                fontWeight: "bold",
                borderRadius: "999px",
                maxWidth: 420,
              }}
            />
          )}
        </Toolbar>
      </AppBar>

      <Box className="section">
        {error && (
          <Alert severity="error" sx={{ mb: 3, borderRadius: 3 }} onClose={() => setError("")}>
            {error}
          </Alert>
        )}

        {/* Scan progress while it is still running */}
        {running && (
          <Paper
            sx={{
              p: 6,
              mb: 4,
              bgcolor: "#FFF",
              border: "1px solid rgba(0, 0, 0, 0.08)",
              borderRadius: 4,
              boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)",
              textAlign: "center",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, mb: 2 }}>
              <CircularProgress sx={{ color: "#E53935" }} size={32} />
              <Typography variant="h4" sx={{ fontWeight: "bold", color: "#1D1D1F" }}>
                Scanning in progress...
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={Math.min(100, Math.max(0, status?.progress ?? 0))}
              sx={{
                height: 10,
                borderRadius: 5,
                mb: 2,
                bgcolor: "#F5F5F7",
                "& .MuiLinearProgress-bar": { borderRadius: 5, bgcolor: "#E53935" },
              }}
            />
            <Typography variant="body1" sx={{ color: "#6E6E73" }}>
              {status?.current_step || "Preparing scan..."}
            </Typography>
            {status?.total_modules > 0 && (
              <Typography variant="body2" sx={{ color: "#86868B" }}>
                {status.completed_modules} of {status.total_modules} modules complete ({status.progress}%)
              </Typography>
            )}
          </Paper>
        )}

        {/* Waiting for the first status answer */}
        {!status && !error && (
          <Paper
            sx={{
              p: 6,
              mb: 4,
              bgcolor: "#FFF",
              border: "1px solid rgba(0, 0, 0, 0.08)",
              borderRadius: 4,
              textAlign: "center",
            }}
          >
            <CircularProgress sx={{ color: "#E53935" }} size={32} />
            <Typography variant="body1" sx={{ color: "#6E6E73", mt: 2 }}>
              Loading scan {scanId || "..."}...
            </Typography>
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
                    {[
                      { key: "critical", label: "Critical", color: "#dc2626", bg: "#FEF2F2", border: "#FECACA" },
                      { key: "high", label: "High", color: "#ea580c", bg: "#FFF7ED", border: "#FED7AA" },
                      { key: "medium", label: "Medium", color: "#d97706", bg: "#FFFBEB", border: "#FDE68A" },
                      { key: "low", label: "Low", color: "#0e7490", bg: "#F0F9FF", border: "#BAE6FD" },
                    ].map((s) => (
                      <Grid item xs={6} sm={3} key={s.key}>
                        <Card sx={{ bgcolor: s.bg, border: `1px solid ${s.border}`, borderRadius: 3 }}>
                          <CardContent sx={{ textAlign: "center", py: 3 }}>
                            <Typography variant="h3" sx={{ color: s.color, fontWeight: 800, lineHeight: 1.1 }}>
                              {results.statistics?.[s.key] || 0}
                            </Typography>
                            <Typography variant="body2" sx={{ color: s.color, fontWeight: "bold", letterSpacing: "0.5px" }}>
                              {s.label}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              </Grid>

              {/* Risk Score */}
              <Grid item xs={12} md={4}>
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
                      sx={{ bgcolor: riskScore.color, color: "white", fontWeight: "bold", mt: 2 }}
                    />
                    <Typography variant="body2" sx={{ color: "#888", mt: 2, display: "block" }}>
                      {riskScore.level === "None"
                        ? "No vulnerabilities detected"
                        : `Overall risk based on ${results.findings.length} findings`}
                    </Typography>
                  </Box>
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
                      {chartData.some((d) => d.value > 0) ? (
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
                            <Tooltip contentStyle={{ backgroundColor: "#FFFFFF", border: "1px solid rgba(0,0,0,0.1)", borderRadius: 10, color: "#1D1D1F" }} />
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

                  {/* Findings by Severity (Bar Chart) */}
                  <Grid item xs={12} md={7}>
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
                            <Tooltip contentStyle={{ backgroundColor: "#FFFFFF", border: "1px solid rgba(0,0,0,0.1)", borderRadius: 10, color: "#1D1D1F" }} cursor={{ fill: "rgba(0,0,0,0.04)" }} />
                            <Bar dataKey="value" fill="#E53935" radius={[0, 6, 6, 0]} />
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
              </Grid>
            </Grid>

            {/* Findings list */}
            <Paper sx={{ bgcolor: "#FFF", border: "1px solid rgba(0, 0, 0, 0.08)", borderRadius: 4, boxShadow: "0 4px 16px rgba(0, 0, 0, 0.08)", overflow: "hidden" }}>
              <Box sx={{ borderBottom: 1, borderColor: "rgba(0, 0, 0, 0.08)", display: "flex", justifyContent: "space-between", alignItems: "center", p: 1, pl: 2, flexWrap: "wrap", gap: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: "bold", color: "#1D1D1F", p: 1 }}>
                  Findings ({results.findings?.length || 0})
                </Typography>
                <Box sx={{ display: "flex", gap: 1, mr: 2 }}>
                  <Chip
                    size="small"
                    icon={<CheckIcon sx={{ fontSize: 16, color: "#FFF !important" }} />}
                    label={status?.status || "completed"}
                    sx={{ bgcolor: "#E53935", color: "#FFF", fontWeight: "bold", borderRadius: "999px" }}
                  />
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<DownloadIcon />}
                    onClick={downloadReport}
                    sx={{ color: "#1D1D1F", borderColor: "rgba(0,0,0,0.2)", "&:hover": { borderColor: "#1D1D1F", bgcolor: "rgba(0,0,0,0.04)" } }}
                  >
                    Report
                  </Button>
                </Box>
              </Box>

              <List sx={{ bgcolor: "transparent", p: 2 }}>
                {results.findings?.length === 0 ? (
                  <Alert severity="info" sx={{ bgcolor: "#252525", color: "#00d4ff" }}>
                    No vulnerabilities found! The target appears to be secure.
                  </Alert>
                ) : (
                  results.findings?.map((finding, index) => {
                    const isExpanded = !!expanded[index];
                    const severityColor = getSeverityColor(finding.severity);
                    return (
                      <Paper
                        key={finding.id || index}
                        sx={{
                          mb: 2,
                          bgcolor: "#252525",
                          borderLeft: `5px solid ${severityColor}`,
                          cursor: "pointer",
                          transition: "all 0.2s",
                          "&:hover": { transform: "translateX(5px)", boxShadow: "0 4px 12px rgba(0,0,0,0.3)" },
                        }}
                        onClick={() => setExpanded((prev) => ({ ...prev, [index]: !prev[index] }))}
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
                                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                                  <Chip
                                    label={finding.type}
                                    size="small"
                                    sx={{ bgcolor: "#00d4ff", color: "#000", fontWeight: "bold" }}
                                  />
                                  <Chip
                                    label={finding.severity}
                                    size="small"
                                    sx={{ bgcolor: severityColor, color: "#FFF", fontWeight: "bold" }}
                                  />
                                </Box>
                              </Box>
                            }
                            secondary={
                              <Typography sx={{ color: "#b0b0b0", mt: 1 }}>
                                {finding.description}
                              </Typography>
                            }
                          />
                          <ListItemIcon sx={{ color: isExpanded ? "#00d4ff" : "#888" }}>
                            {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </ListItemIcon>
                        </ListItem>
                        {isExpanded && (
                          <Box sx={{ px: 3, pb: 2 }}>
                            <Divider sx={{ bgcolor: "#444", mb: 2 }} />
                            <Typography variant="body2" sx={{ color: "#888" }}>
                              <strong style={{ color: "#00d4ff" }}>URL:</strong>{" "}
                              <code style={{ color: "#00ff00", backgroundColor: "#1e1e1e", padding: "2px 6px", borderRadius: "4px" }}>
                                {finding.url || "N/A"}
                              </code>
                              <CopyButton text={finding.url} label="Copy URL" />
                            </Typography>
                            {finding.payload && (
                              <Typography variant="body2" sx={{ color: "#888", mt: 1 }}>
                                <strong style={{ color: "#00d4ff" }}>Payload:</strong>{" "}
                                <code style={{ color: "#ff6b6b", backgroundColor: "#1e1e1e", padding: "2px 6px", borderRadius: "4px" }}>
                                  {finding.payload}
                                </code>
                                <CopyButton text={finding.payload} label="Copy Payload" />
                              </Typography>
                            )}
                            <PocBlock poc={finding.poc} />
                          </Box>
                        )}
                      </Paper>
                    );
                  })
                )}
              </List>
            </Paper>
          </>
        )}

        {/* Finished, but nothing stored */}
        {status &&
          (status.status === "completed" || status.status === "cancelled") &&
          !results && (
            <Alert severity="info" sx={{ borderRadius: 3 }}>
              The scan has finished but its results are no longer available. Run
              the scan again from the main window.
            </Alert>
          )}
      </Box>
    </Box>
  );
}

