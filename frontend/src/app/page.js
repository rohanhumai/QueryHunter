"use client";

import { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  Bot,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  Filter,
  Menu,
  MessageSquare,
  Search,
  Settings,
  Shield,
  Sparkles,
  Terminal,
  X,
  Zap,
} from "lucide-react";

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";

/* =========================================================
   DEMO DATA
========================================================= */

const logsData = [
  {
    id: 1,
    time: "20:41:08",
    source: "185.220.101.14",
    destination: "10.0.0.15",
    attack: "Brute Force",
    action: "DENY",
    protocol: "TCP",
    risk: 92,
  },
  {
    id: 2,
    time: "20:37:21",
    source: "45.155.205.33",
    destination: "10.0.0.21",
    attack: "DoS",
    action: "DENY",
    protocol: "TCP",
    risk: 87,
  },
  {
    id: 3,
    time: "20:31:44",
    source: "172.16.8.42",
    destination: "10.0.0.12",
    attack: "Port Scan",
    action: "ALERT",
    protocol: "TCP",
    risk: 64,
  },
  {
    id: 4,
    time: "20:28:11",
    source: "192.168.4.91",
    destination: "10.0.0.18",
    attack: "Normal",
    action: "ALLOW",
    protocol: "HTTP",
    risk: 8,
  },
  {
    id: 5,
    time: "20:22:39",
    source: "91.240.118.172",
    destination: "10.0.0.25",
    attack: "Botnet",
    action: "DENY",
    protocol: "UDP",
    risk: 78,
  },
  {
    id: 6,
    time: "20:18:05",
    source: "103.77.192.18",
    destination: "10.0.0.31",
    attack: "Brute Force",
    action: "DENY",
    protocol: "TCP",
    risk: 95,
  },
  {
    id: 7,
    time: "20:14:52",
    source: "51.68.142.12",
    destination: "10.0.0.14",
    attack: "DoS",
    action: "DENY",
    protocol: "TCP",
    risk: 89,
  },
  {
    id: 8,
    time: "20:10:31",
    source: "10.20.2.44",
    destination: "10.0.0.19",
    attack: "Normal",
    action: "ALLOW",
    protocol: "HTTP",
    risk: 5,
  },
  {
    id: 9,
    time: "20:05:16",
    source: "185.220.101.14",
    destination: "10.0.0.22",
    attack: "Port Scan",
    action: "ALERT",
    protocol: "TCP",
    risk: 69,
  },
  {
    id: 10,
    time: "20:01:43",
    source: "91.240.118.172",
    destination: "10.0.0.16",
    attack: "Botnet",
    action: "DENY",
    protocol: "UDP",
    risk: 81,
  },
  {
    id: 11,
    time: "19:57:32",
    source: "103.77.192.18",
    destination: "10.0.0.20",
    attack: "Brute Force",
    action: "DENY",
    protocol: "TCP",
    risk: 91,
  },
  {
    id: 12,
    time: "19:53:21",
    source: "192.168.4.31",
    destination: "10.0.0.11",
    attack: "Normal",
    action: "ALLOW",
    protocol: "HTTP",
    risk: 6,
  },
];

const attackDistribution = [
  { name: "Brute Force", value: 38 },
  { name: "DoS", value: 31 },
  { name: "Port Scan", value: 22 },
  { name: "Botnet", value: 17 },
  { name: "Normal", value: 92 },
];

const COLORS = ["#22d3ee", "#f97316", "#a78bfa", "#ef4444", "#34d399"];

const suggestions = [
  "Show brute force attacks",
  "Find all DoS attacks",
  "Show denied traffic",
  "Find high risk events",
];

/* =========================================================
   MAIN COMPONENT
========================================================= */

export default function Home() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [question, setQuestion] = useState("");

  const [attackFilter, setAttackFilter] = useState("All");
  const [actionFilter, setActionFilter] = useState("All");

  const [currentPage, setCurrentPage] = useState(1);

  const [answer, setAnswer] = useState(null);

  const [loading, setLoading] = useState(false);

  const rowsPerPage = 6;

  /* =====================================================
     FILTER LOGS
  ===================================================== */

  const filteredLogs = useMemo(() => {
    return logsData.filter((log) => {
      const attackMatch = attackFilter === "All" || log.attack === attackFilter;

      const actionMatch = actionFilter === "All" || log.action === actionFilter;

      return attackMatch && actionMatch;
    });
  }, [attackFilter, actionFilter]);

  /* =====================================================
     PAGINATION
  ===================================================== */

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / rowsPerPage));

  const safePage = Math.min(currentPage, totalPages);

  const paginatedLogs = filteredLogs.slice(
    (safePage - 1) * rowsPerPage,
    safePage * rowsPerPage,
  );

  /* =====================================================
     AI QUERY
  ===================================================== */

  const runAIQuery = async () => {
    if (!question.trim()) return;

    setLoading(true);

    /*
      BACKEND CONNECTION WILL GO HERE:

      POST http://localhost:8000/ask

      {
        "question": question
      }

      Expected:

      {
        "query": "...",
        "results": [...],
        "explanation": "...",
        "risk_score": 92
      }
    */

    setTimeout(() => {
      const lower = question.toLowerCase();

      let generatedSQL = "SELECT * FROM security_logs LIMIT 50;";

      let explanation =
        "QueryHunter analyzed your natural-language request and searched the security log dataset.";

      let risk = 52;

      if (lower.includes("brute")) {
        generatedSQL =
          "SELECT * FROM security_logs WHERE attack_type = 'Brute Force';";

        explanation =
          "The query was interpreted as a request to find brute-force activity. QueryHunter filtered the security logs using the attack_type field.";

        risk = 92;
      } else if (lower.includes("dos")) {
        generatedSQL = "SELECT * FROM security_logs WHERE attack_type = 'DoS';";

        explanation =
          "The query was interpreted as a denial-of-service investigation. Results were filtered for DoS activity.";

        risk = 87;
      } else if (lower.includes("denied")) {
        generatedSQL = "SELECT * FROM security_logs WHERE action = 'DENY';";

        explanation =
          "The request was interpreted as a search for denied network activity. QueryHunter filtered records where the security action was DENY.";

        risk = 78;
      } else if (lower.includes("high risk")) {
        generatedSQL =
          "SELECT * FROM security_logs WHERE risk_score >= 80 ORDER BY risk_score DESC;";

        explanation =
          "QueryHunter identified a high-risk investigation and selected events whose calculated risk score is 80 or higher.";

        risk = 95;
      }

      setAnswer({
        query: generatedSQL,
        explanation,
        risk,
      });

      setLoading(false);

      setTimeout(() => {
        document.getElementById("explanation")?.scrollIntoView({
          behavior: "smooth",
        });
      }, 100);
    }, 800);
  };

  /* =====================================================
     CSV EXPORT
  ===================================================== */

  const exportCSV = () => {
    const headers = [
      "Time",
      "Source IP",
      "Destination",
      "Attack Type",
      "Action",
      "Protocol",
      "Risk",
    ];

    const rows = filteredLogs.map((log) => [
      log.time,
      log.source,
      log.destination,
      log.attack,
      log.action,
      log.protocol,
      log.risk,
    ]);

    const csv = [
      headers.join(","),
      ...rows.map((row) => row.map((value) => `"${value}"`).join(",")),
    ].join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download = "queryhunter-security-logs.csv";

    link.click();

    URL.revokeObjectURL(url);
  };

  /* =====================================================
     FILTER HANDLER
  ===================================================== */

  const changeAttackFilter = (value) => {
    setAttackFilter(value);
    setCurrentPage(1);
  };

  const changeActionFilter = (value) => {
    setActionFilter(value);
    setCurrentPage(1);
  };

  /* =====================================================
     UI
  ===================================================== */

  return (
    <div className="min-h-screen bg-[#070b12] text-white">
      {/* MOBILE OVERLAY */}

      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* =================================================
          SIDEBAR
      ================================================= */}

      <aside
        className={`
          fixed left-0 top-0 z-50
          flex h-screen w-64 flex-col
          border-r border-white/10
          bg-[#090e17]
          transition-transform duration-300
          lg:translate-x-0
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        {/* LOGO */}

        <div className="flex h-20 items-center gap-3 border-b border-white/10 px-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/10">
            <Shield size={21} />
          </div>

          <div>
            <h1 className="font-bold tracking-tight">QueryHunter</h1>

            <p className="text-[9px] font-bold tracking-[0.2em] text-cyan-400/70">
              AI SECURITY
            </p>
          </div>

          <button
            className="ml-auto text-slate-500 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={19} />
          </button>
        </div>

        {/* NAVIGATION */}

        <nav className="flex-1 px-3 py-6">
          <p className="mb-3 px-3 text-[9px] font-bold tracking-[0.2em] text-slate-600">
            WORKSPACE
          </p>

          <SidebarItem
            href="#overview"
            icon={<Activity size={17} />}
            text="Overview"
            active
          />

          <SidebarItem
            href="#ai-search"
            icon={<Sparkles size={17} />}
            text="AI Search"
          />

          <SidebarItem
            href="#logs"
            icon={<Database size={17} />}
            text="Security Logs"
          />

          <SidebarItem
            href="#analytics"
            icon={<BarChart3 size={17} />}
            text="Analytics"
          />

          <SidebarItem
            href="#explanation"
            icon={<MessageSquare size={17} />}
            text="AI Explanation"
          />
        </nav>

        {/* AI ENGINE */}

        <div className="m-4 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.035] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300">
            <Zap size={14} />
            AI ENGINE
          </div>

          <p className="mt-2 text-[10px] leading-5 text-slate-500">
            Natural language → SQL → security insight
          </p>

          <div className="mt-3 flex items-center gap-2 text-[10px] text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Model ready
          </div>
        </div>
      </aside>

      {/* =================================================
          MAIN
      ================================================= */}

      <main className="lg:ml-64">
        {/* TOPBAR */}

        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-white/10 bg-[#070b12]/80 px-5 backdrop-blur-xl sm:px-8">
          <div className="flex items-center gap-3">
            <button
              className="rounded-lg border border-white/10 p-2 text-slate-400 lg:hidden"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={19} />
            </button>

            <div>
              <div className="text-sm font-semibold">Security Operations</div>

              <div className="mt-1 text-[10px] text-slate-600">
                Natural language threat hunting
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <Bell size={17} className="hidden text-slate-600 sm:block" />

            <Settings size={17} className="hidden text-slate-600 sm:block" />

            <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-[10px] text-slate-500">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              System Online
            </div>
          </div>
        </header>

        {/* =================================================
            DASHBOARD
        ================================================= */}

        <div className="mx-auto max-w-[1450px] space-y-6 p-5 sm:p-8">
          {/* HERO */}

          <section id="overview">
            <div className="flex items-center gap-2 text-[9px] font-bold tracking-[0.2em] text-cyan-300">
              <Sparkles size={13} />
              AI-POWERED SECURITY HUNTING
            </div>

            <h1 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
              QueryHunter <span className="text-cyan-300">AI</span>
            </h1>

            <p className="mt-2 max-w-2xl text-xs leading-6 text-slate-500 sm:text-sm">
              Search and analyze security logs using plain English instead of
              complex SQL or SPL queries.
            </p>
          </section>

          {/* =================================================
              STAT CARDS
          ================================================= */}

          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={<Database size={18} />}
              title="Security Logs"
              value="10,842"
              description="Total records"
            />

            <StatCard
              icon={<AlertTriangle size={18} />}
              title="Threat Events"
              value="1,284"
              description="Detected attacks"
            />

            <StatCard
              icon={<Shield size={18} />}
              title="High Risk"
              value="247"
              description="Critical events"
            />

            <StatCard
              icon={<Activity size={18} />}
              title="Response Time"
              value="< 1s"
              description="Average query target"
            />
          </section>

          {/* =================================================
              AI SEARCH
          ================================================= */}

          <section
            id="ai-search"
            className="rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.035] p-5 sm:p-6"
          >
            <div className="mb-5 flex gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-400/10 text-cyan-300">
                <Bot size={19} />
              </div>

              <div>
                <h2 className="text-sm font-semibold">Ask QueryHunter</h2>

                <p className="mt-1 text-[10px] leading-5 text-slate-600">
                  Ask security questions in natural language and let AI
                  translate them into database queries.
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-[#05090f] p-2 sm:flex-row">
              <div className="flex flex-1 items-center gap-3 px-3">
                <Search size={17} className="text-slate-600" />

                <input
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      runAIQuery();
                    }
                  }}
                  placeholder="Show me all brute force attacks from yesterday..."
                  className="w-full bg-transparent py-3 text-xs text-white outline-none placeholder:text-slate-700"
                />
              </div>

              <button
                onClick={runAIQuery}
                disabled={loading}
                className="flex items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 py-3 text-xs font-bold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Sparkles size={14} />

                {loading ? "Analyzing..." : "Analyze"}
              </button>
            </div>

            {/* SUGGESTIONS */}

            <div className="mt-3 flex flex-wrap gap-2">
              {suggestions.map((item) => (
                <button
                  key={item}
                  onClick={() => setQuestion(item)}
                  className="rounded-full border border-white/10 px-3 py-1.5 text-[10px] text-slate-500 transition hover:border-cyan-400/20 hover:text-cyan-300"
                >
                  {item}
                </button>
              ))}
            </div>
          </section>

          {/* =================================================
              ANALYTICS
          ================================================= */}

          <section id="analytics" className="grid gap-5 xl:grid-cols-2">
            {/* BAR CHART */}

            <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="mb-5 flex items-start justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Attack Distribution</h2>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Security events by attack category
                  </p>
                </div>

                <BarChart3 size={17} className="text-slate-600" />
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackDistribution}>
                    <CartesianGrid
                      stroke="#172130"
                      strokeDasharray="3 3"
                      vertical={false}
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: "#64748b",
                        fontSize: 10,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      tick={{
                        fill: "#64748b",
                        fontSize: 10,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        background: "#0b111b",
                        border: "1px solid #263244",
                        borderRadius: "10px",
                        color: "#fff",
                        fontSize: "11px",
                      }}
                    />

                    <Bar dataKey="value" fill="#22d3ee" radius={[5, 5, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* PIE CHART */}

            <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="mb-5 flex items-start justify-between">
                <div>
                  <h2 className="text-sm font-semibold">Threat Mix</h2>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Distribution of detected activity
                  </p>
                </div>

                <Shield size={17} className="text-slate-600" />
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={attackDistribution}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={3}
                    >
                      {attackDistribution.map((_, index) => (
                        <Cell
                          key={index}
                          fill={COLORS[index % COLORS.length]}
                        />
                      ))}
                    </Pie>

                    <Tooltip
                      contentStyle={{
                        background: "#0b111b",
                        border: "1px solid #263244",
                        borderRadius: "10px",
                        color: "#fff",
                        fontSize: "11px",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="grid grid-cols-2 gap-2">
                {attackDistribution.map((item, index) => (
                  <div
                    key={item.name}
                    className="flex items-center gap-2 text-[10px] text-slate-500"
                  >
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{
                        background: COLORS[index % COLORS.length],
                      }}
                    />

                    {item.name}
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* =================================================
              SECURITY LOGS
          ================================================= */}

          <section id="logs">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold">Security Logs</h2>

                <p className="mt-1 text-[10px] text-slate-600">
                  Interactive security event results
                </p>
              </div>

              <button
                onClick={exportCSV}
                className="flex w-fit items-center gap-2 rounded-lg border border-white/10 bg-white/[0.025] px-3 py-2 text-[10px] text-slate-400 transition hover:bg-white/5 hover:text-white"
              >
                <Download size={14} />
                Export CSV
              </button>
            </div>

            {/* FILTERS */}

            <div className="mb-3 flex flex-wrap gap-2">
              <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.025] px-3">
                <Filter size={13} className="text-slate-600" />

                <select
                  value={attackFilter}
                  onChange={(e) => changeAttackFilter(e.target.value)}
                  className="bg-transparent py-2.5 text-[10px] text-slate-400 outline-none"
                >
                  <option value="All" className="bg-[#0b111b]">
                    All attacks
                  </option>

                  <option value="Brute Force" className="bg-[#0b111b]">
                    Brute Force
                  </option>

                  <option value="DoS" className="bg-[#0b111b]">
                    DoS
                  </option>

                  <option value="Port Scan" className="bg-[#0b111b]">
                    Port Scan
                  </option>

                  <option value="Botnet" className="bg-[#0b111b]">
                    Botnet
                  </option>

                  <option value="Normal" className="bg-[#0b111b]">
                    Normal
                  </option>
                </select>
              </div>

              <div className="flex items-center rounded-lg border border-white/10 bg-white/[0.025] px-3">
                <select
                  value={actionFilter}
                  onChange={(e) => changeActionFilter(e.target.value)}
                  className="bg-transparent py-2.5 text-[10px] text-slate-400 outline-none"
                >
                  <option value="All" className="bg-[#0b111b]">
                    All actions
                  </option>

                  <option value="DENY" className="bg-[#0b111b]">
                    DENY
                  </option>

                  <option value="ALLOW" className="bg-[#0b111b]">
                    ALLOW
                  </option>

                  <option value="ALERT" className="bg-[#0b111b]">
                    ALERT
                  </option>
                </select>
              </div>

              <div className="flex items-center px-2 text-[10px] text-slate-600">
                {filteredLogs.length} results
              </div>
            </div>

            {/* TABLE */}

            <div className="overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.02]">
              <table className="w-full min-w-[900px]">
                <thead>
                  <tr className="border-b border-white/10 bg-white/[0.02]">
                    <TableHead>TIME</TableHead>

                    <TableHead>SOURCE IP</TableHead>

                    <TableHead>DESTINATION</TableHead>

                    <TableHead>ATTACK TYPE</TableHead>

                    <TableHead>ACTION</TableHead>

                    <TableHead>PROTOCOL</TableHead>

                    <TableHead>RISK</TableHead>
                  </tr>
                </thead>

                <tbody>
                  {paginatedLogs.map((log) => (
                    <tr
                      key={log.id}
                      className="border-b border-white/5 transition hover:bg-white/[0.02]"
                    >
                      <TableCell>{log.time}</TableCell>

                      <TableCell mono>{log.source}</TableCell>

                      <TableCell mono>{log.destination}</TableCell>

                      <TableCell>
                        <span className="rounded-md bg-white/[0.05] px-2 py-1 text-[9px] text-slate-400">
                          {log.attack}
                        </span>
                      </TableCell>

                      <TableCell>
                        <ActionBadge action={log.action} />
                      </TableCell>

                      <TableCell>{log.protocol}</TableCell>

                      <TableCell>
                        <RiskBadge score={log.risk} />
                      </TableCell>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* PAGINATION */}

            <div className="mt-3 flex items-center justify-between">
              <p className="text-[10px] text-slate-600">
                Page {safePage} of {totalPages}
              </p>

              <div className="flex gap-2">
                <button
                  disabled={safePage === 1}
                  onClick={() => setCurrentPage((page) => page - 1)}
                  className="rounded-lg border border-white/10 p-2 text-slate-500 disabled:opacity-30"
                >
                  <ChevronLeft size={14} />
                </button>

                <button
                  disabled={safePage === totalPages}
                  onClick={() => setCurrentPage((page) => page + 1)}
                  className="rounded-lg border border-white/10 p-2 text-slate-500 disabled:opacity-30"
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </section>

          {/* =================================================
              AI EXPLANATION
          ================================================= */}

          <section
            id="explanation"
            className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]"
          >
            {/* EXPLANATION */}

            <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-400/10 text-violet-300">
                  <MessageSquare size={18} />
                </div>

                <div>
                  <h2 className="text-sm font-semibold">Explainable AI</h2>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Understand why QueryHunter returned these results.
                  </p>
                </div>
              </div>

              {answer ? (
                <>
                  <div className="mt-5 rounded-xl border border-white/10 bg-[#05090f] p-4">
                    <p className="text-[11px] leading-6 text-slate-400">
                      {answer.explanation}
                    </p>
                  </div>

                  <div className="mt-5 flex items-center gap-2 text-[9px] font-bold tracking-wider text-slate-600">
                    <Terminal size={13} />
                    GENERATED SQL
                  </div>

                  <pre className="mt-2 overflow-x-auto rounded-xl border border-white/10 bg-[#04070c] p-4 text-[10px] leading-6 text-cyan-300">
                    {answer.query}
                  </pre>
                </>
              ) : (
                <div className="flex min-h-[210px] flex-col items-center justify-center text-center">
                  <Bot size={30} className="text-slate-700" />

                  <p className="mt-3 max-w-sm text-[11px] leading-5 text-slate-600">
                    Ask a natural-language question above to generate the SQL
                    query and AI explanation.
                  </p>
                </div>
              )}
            </div>

            {/* RISK */}

            <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-400/10 text-red-300">
                  <AlertTriangle size={18} />
                </div>

                <div>
                  <h2 className="text-sm font-semibold">Risk Assessment</h2>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Automatic threat severity
                  </p>
                </div>
              </div>

              <div className="mt-6 flex items-center gap-5">
                <div className="flex h-28 w-28 shrink-0 flex-col items-center justify-center rounded-full border-[8px] border-red-500/10 bg-red-500/[0.025]">
                  <strong className="text-2xl">
                    {answer ? answer.risk : "—"}
                  </strong>

                  <span className="text-[8px] tracking-widest text-slate-600">
                    SCORE
                  </span>
                </div>

                <div>
                  <h3 className="text-xs font-bold text-red-300">
                    {answer ? getRiskLabel(answer.risk) : "AWAITING QUERY"}
                  </h3>

                  <p className="mt-2 text-[10px] leading-5 text-slate-600">
                    Risk severity is calculated from threat patterns detected in
                    the security logs.
                  </p>
                </div>
              </div>

              {/* SYSTEM STATUS */}

              <div className="mt-7 space-y-3">
                <StatusRow label="AI Model" value="Mistral 7B" />

                <StatusRow label="Database" value="Connected" />

                <StatusRow label="Dataset" value="CICIDS2017" />

                <StatusRow label="Backend" value="FastAPI" />
              </div>
            </div>
          </section>

          {/* FOOTER */}

          <footer className="flex flex-col justify-between gap-2 border-t border-white/10 py-6 text-[9px] text-slate-700 sm:flex-row">
            <span>QueryHunter AI</span>

            <span>Natural Language Security Log Analyzer</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

/* =========================================================
   COMPONENTS
========================================================= */

function SidebarItem({ href, icon, text, active }) {
  return (
    <a
      href={href}
      className={`mb-1 flex items-center gap-3 rounded-xl px-3 py-3 text-xs transition ${
        active
          ? "bg-white/[0.05] text-white"
          : "text-slate-500 hover:bg-white/[0.04] hover:text-white"
      }`}
    >
      {icon}

      {text}
    </a>
  );
}

function StatCard({ icon, title, value, description }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300">
        {icon}
      </div>

      <div className="mt-5 text-2xl font-bold">{value}</div>

      <div className="mt-1 text-xs text-slate-400">{title}</div>

      <div className="mt-2 text-[10px] text-slate-600">{description}</div>
    </div>
  );
}

function TableHead({ children }) {
  return (
    <th className="px-4 py-3 text-left text-[8px] font-bold tracking-wider text-slate-600">
      {children}
    </th>
  );
}

function TableCell({ children, mono }) {
  return (
    <td
      className={`px-4 py-3 text-[10px] text-slate-500 ${
        mono ? "font-mono text-slate-400" : ""
      }`}
    >
      {children}
    </td>
  );
}

function ActionBadge({ action }) {
  const styles = {
    DENY: "bg-red-500/10 text-red-300",
    ALLOW: "bg-emerald-500/10 text-emerald-300",
    ALERT: "bg-orange-500/10 text-orange-300",
  };

  return (
    <span
      className={`rounded-md px-2 py-1 text-[8px] font-bold ${
        styles[action] || ""
      }`}
    >
      {action}
    </span>
  );
}

function RiskBadge({ score }) {
  let style = "";

  if (score >= 80) {
    style = "bg-red-500/10 text-red-300";
  } else if (score >= 60) {
    style = "bg-orange-500/10 text-orange-300";
  } else if (score >= 30) {
    style = "bg-yellow-500/10 text-yellow-300";
  } else {
    style = "bg-emerald-500/10 text-emerald-300";
  }

  return (
    <span className={`rounded-full px-2 py-1 text-[8px] font-bold ${style}`}>
      {score}
    </span>
  );
}

function StatusRow({ label, value }) {
  return (
    <div className="flex items-center justify-between border-b border-white/5 pb-3 text-[10px]">
      <span className="text-slate-600">{label}</span>

      <span className="flex items-center gap-1.5 text-slate-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

        {value}
      </span>
    </div>
  );  
}

function getRiskLabel(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}
