import { useEffect, useMemo, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import {
  AlertTriangle,
  AppWindow,
  BarChart3,
  Bell,
  ChevronRight,
  Globe,
  LayoutDashboard,
  Lock,
  Search,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  TrendingUp,
  Settings,
  FileText,
  Activity,
  ArrowUpRight,
  Trash2,
  Pencil,
  Plus,
  Menu,
  X,
  ScanLine,
  Users,
  Flag,
  GitBranch,
  BadgeCheck,
  MessageCircle,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const navItems = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard },
  { key: 'ai-chat', label: 'AI Chat', icon: MessageCircle },
  { key: 'brands', label: 'Brand Profiles', icon: ShieldCheck },
  { key: 'social', label: 'Social Monitoring', icon: Globe },
  { key: 'apps', label: 'App Monitoring', icon: AppWindow },
  { key: 'dna', label: 'Scam DNA', icon: Sparkles },
  { key: 'investigations', label: 'Investigations', icon: Activity },
  { key: 'reports', label: 'Reports', icon: FileText },
  { key: 'campaigns', label: 'Campaign Evolution', icon: GitBranch },
  { key: 'community', label: 'Community Reports', icon: Users },
  { key: 'qr', label: 'QR Safety Scanner', icon: ScanLine },
  { key: 'trust', label: 'Trust Center', icon: BadgeCheck },
  { key: 'portal', label: 'Report a Scam', icon: Flag },
  { key: 'settings', label: 'Settings', icon: Settings },
];

type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
type RiskCategory = 'suspicious' | 'inconclusive' | 'lower_risk';
type AnalysisIndicator = {
  code: string;
  severity: string;
  source: string;
  message: string;
};
type AnalysisResult = {
  id: number;
  entity_name: string;
  risk_score: number;
  risk_level: RiskLevel;
  risk_category: RiskCategory;
  explanation: string;
  url: string;
  indicators: AnalysisIndicator[];
  evidence: { type: string; value: string; confidence: number }[];
};

type Brand = {
  id: number;
  name: string;
  company_description: string;
  industry: string;
  official_website: string;
  official_social_accounts: string[];
  official_mobile_apps: string[];
  official_package_ids: string[];
  official_developer_names: string[];
  brand_keywords: string[];
  known_domains: string[];
  logo_path: string;
  additional_identifiers: Record<string, string>;
  is_sample: boolean;
};

type Detection = {
  id: number;
  brand_id: number;
  entity_name: string;
  entity_type: string;
  platform: string;
  similarity_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  detection_reason: string;
  status: string;
  evidence: Record<string, any>;
  detected_at: string;
};

type FindingDetails = Detection & {
  investigation_ids: number[];
  evidence_records: { id: number; type: string; value: string; confidence: number; details: Record<string, unknown>; created_at: string | null }[];
};

type Investigation = {
  id: number;
  brand_id: number;
  detection_id: number | null;
  title: string;
  summary: string;
  status: string;
  risk_level: RiskLevel;
  created_at: string;
};

type DashboardData = {
  summary: {
    total_brands: number;
    social_profiles_analyzed: number;
    applications_analyzed: number;
    potential_impersonations: number;
    critical_risk_findings: number;
    official_assets_protected: number;
  };
  platform_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
  detections: Detection[];
  findings_by_month: { name: string; value: number }[];
};

type Campaign = {
  id: number;
  brand_id: number;
  title: string;
  campaign_key: string;
  status: string;
  event_count: number;
  linked_finding_count: number;
  risk_summary: Record<RiskLevel, number>;
  events: {
    id: number;
    detection_id: number | null;
    event_type: string;
    summary: string;
    indicators: Record<string, unknown>;
    risk_level: RiskLevel | null;
    risk_score: number | null;
    finding_status: string | null;
    finding_available: boolean;
    created_at: string | null;
  }[];
};

type CommunityReport = {
  id: number;
  brand_id: number | null;
  report_text: string;
  reported_url: string;
  status: string;
  created_at: string | null;
  matches: { detection_id: number; score: number; reason: string; analyst_verified: boolean }[];
};

type GraphNode = {
  id: string;
  label: string;
  kind: string;
  [key: string]: unknown;
};
type GraphEdge = {
  source: string;
  target: string;
  relation: string;
  confidence?: number;
  [key: string]: unknown;
};

type ReportData = {
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    risk_score_avg: number;
  };
  findings: { entity_name: string; risk_level: RiskLevel; platform: string; risk_score: number }[];
};

type ChatMessage = {
  id: number;
  role: 'user' | 'assistant';
  content: string;
};

const toInputValue = (value: unknown) => Array.isArray(value) ? value.join(',') : typeof value === 'string' ? value : '';
const apiErrorMessage = async (response: Response, fallback: string) => {
  const body = await response.clone().json().catch(() => ({}));
  return typeof body.detail === 'string' ? body.detail : `${fallback} (HTTP ${response.status}).`;
};

const apiFetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const buildHeaders = () => {
    const headers = new Headers(init.headers);
    const token = localStorage.getItem('brandshield_access_token');
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return headers;
  };
  let response = await fetch(input, { ...init, headers: buildHeaders() });
  if (response.status === 401 && String(input) !== '/api/auth/login') {
    localStorage.removeItem('brandshield_access_token');
    const login = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'analyst@brandshield.local', password: 'brandshield-demo' }),
    });
    if (login.ok) {
      const session = await login.json();
      localStorage.setItem('brandshield_access_token', session.access_token);
      response = await fetch(input, { ...init, headers: buildHeaders() });
    }
  }
  return response;
};

const riskColors: Record<RiskLevel, string> = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#facc15',
  low: '#22c55e',
};

const statusBadgeClass = (status: string) => {
  if (status === 'critical' || status === 'open') return 'bg-red-500/10 text-red-300 border border-red-500/30';
  if (status === 'high' || status === 'monitoring') return 'bg-orange-500/10 text-orange-300 border border-orange-500/30';
  if (status === 'medium' || status === 'review') return 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30';
  return 'bg-green-500/10 text-green-300 border border-green-500/30';
};

function App() {
  const [selectedTab, setSelectedTab] = useState('overview');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [findingDetails, setFindingDetails] = useState<FindingDetails | null>(null);
  const [loadingFindingId, setLoadingFindingId] = useState<number | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [editingInvestigationId, setEditingInvestigationId] = useState<number | null>(null);
  const [investigationDraft, setInvestigationDraft] = useState<{ title: string; summary: string; risk_level: RiskLevel; detection_id: number | null }>({ title: '', summary: '', risk_level: 'medium', detection_id: null });
  const [sources, setSources] = useState<any[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [communityReports, setCommunityReports] = useState<CommunityReport[]>([]);
  const [qrHistory, setQrHistory] = useState<any[]>([]);
  const [trustAssets, setTrustAssets] = useState<any>(null);
  const [copilotResult, setCopilotResult] = useState<any>(null);
  const [customerReportResult, setCustomerReportResult] = useState<any>(null);
  const [qrResult, setQrResult] = useState<any>(null);
  const [qrError, setQrError] = useState<string | null>(null);
  const [isQrAnalyzing, setIsQrAnalyzing] = useState(false);
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [settings, setSettings] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [brandForm, setBrandForm] = useState({
    id: '',
    name: '',
    company_description: '',
    industry: '',
    official_website: '',
    official_social_accounts: '',
    official_mobile_apps: '',
    official_package_ids: '',
    official_developer_names: '',
    brand_keywords: '',
    known_domains: '',
    additional_identifiers: '',
  });
  const [candidateForm, setCandidateForm] = useState({
    name: '',
    url: '',
    description: '',
    entity_type: 'social_profile',
    platform: 'Instagram',
    package_id: '',
    developer_name: '',
  });
  const [sourceForm, setSourceForm] = useState({ platform: 'Instagram', locator: '' });
  const [threatFeedInterval, setThreatFeedInterval] = useState(360);
  const [activeBrandId, setActiveBrandId] = useState<number | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [dashboardFilters, setDashboardFilters] = useState({
    brand: 'all',
    platform: 'all',
    risk: 'all',
    entity: 'all',
    status: 'all',
  });
  const [isLoading, setIsLoading] = useState(true);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatError, setChatError] = useState<string | null>(null);
  const [isChatSending, setIsChatSending] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [chatMessages, isChatSending]);

  const fetchAll = async () => {
    setIsLoading(true);
    try {
      const [brandsRes, detectionsRes, investigationsRes, dashboardRes, reportsRes, settingsRes, healthRes, sourcesRes, graphRes, campaignsRes, communityRes, qrRes] = await Promise.all([
        apiFetch('/api/brands'),
        apiFetch('/api/detections'),
        apiFetch('/api/investigations'),
        apiFetch('/api/dashboard'),
        apiFetch('/api/reports'),
        apiFetch('/api/settings'),
        apiFetch('/api/health'),
        apiFetch('/api/sources'),
        apiFetch('/api/scam-dna/graph'),
        apiFetch('/api/campaigns'),
        apiFetch('/api/community/reports'),
        apiFetch('/api/qr/history'),
      ]);
      const failedResponse = [brandsRes, detectionsRes, investigationsRes, dashboardRes, reportsRes, settingsRes, healthRes, sourcesRes, graphRes, campaignsRes, communityRes, qrRes].find((response) => !response.ok);
      if (failedResponse) {
        const errorBody = await failedResponse.json().catch(() => ({}));
        throw new Error(errorBody.detail || `API request failed with HTTP ${failedResponse.status}.`);
      }
      const [brandsData, detectionsData, investigationsData, dashboardData, reportsData, settingsData, healthData, sourcesData, graphDataResult, campaignsData, communityData, qrData] = await Promise.all([
        brandsRes.json(),
        detectionsRes.json(),
        investigationsRes.json(),
        dashboardRes.json(),
        reportsRes.json(),
        settingsRes.json(),
        healthRes.json(),
        sourcesRes.json(),
        graphRes.json(),
        campaignsRes.json(),
        communityRes.json(),
        qrRes.json(),
      ]);
      setBrands(brandsData);
      setDetections(detectionsData);
      setInvestigations(investigationsData);
      setDashboard(dashboardData);
      setReportData(reportsData);
      setSettings(settingsData);
      setHealth(healthData);
      setSources(sourcesData);
      setGraphData(graphDataResult);
      setSelectedGraphNodeId((current) =>
        graphDataResult.nodes.some((node: GraphNode) => node.id === current)
          ? current
          : graphDataResult.nodes[0]?.id || null,
      );
      setCampaigns(campaignsData);
      setCommunityReports(communityData);
      setQrHistory(qrData);
      setApiError(null);
      if (!activeBrandId && brandsData[0]) setActiveBrandId(brandsData[0].id);
    } catch (error) {
      console.error('Failed to load data', error);
      setApiError(error instanceof Error ? error.message : 'Could not load platform data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const startSession = async () => {
      try {
        if (!localStorage.getItem('brandshield_access_token')) {
          const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'analyst@brandshield.local', password: 'brandshield-demo' }),
          });
          if (!response.ok) throw new Error('Could not start the local demo analyst session.');
          const session = await response.json();
          localStorage.setItem('brandshield_access_token', session.access_token);
        }
        await fetchAll();
      } catch (error) {
        console.error('Unable to start authenticated session', error);
        setApiError(error instanceof Error ? error.message : 'Could not start the authenticated session.');
        setIsLoading(false);
      }
    };
    void startSession();
  }, []);

  useEffect(() => {
    if (!activeBrandId) return;
    apiFetch(`/api/brands/${activeBrandId}/trust`)
      .then(async (response) => {
        if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not load the brand trust center'));
        setTrustAssets(await response.json());
      })
      .catch((error) => {
        console.error('Brand trust center request failed', error);
        setActionError(error instanceof Error ? error.message : 'Could not load the brand trust center.');
      });
  }, [activeBrandId]);

  const summaryCards = dashboard?.summary ? [
    { label: 'Total monitored brands', value: dashboard.summary.total_brands, icon: ShieldCheck, accent: 'cyan' },
    { label: 'Social profiles analyzed', value: dashboard.summary.social_profiles_analyzed, icon: Globe, accent: 'violet' },
    { label: 'Applications analyzed', value: dashboard.summary.applications_analyzed, icon: AppWindow, accent: 'orange' },
    { label: 'Potential impersonations', value: dashboard.summary.potential_impersonations, icon: AlertTriangle, accent: 'red' },
    { label: 'Critical-risk findings', value: dashboard.summary.critical_risk_findings, icon: ShieldOff, accent: 'red' },
    { label: 'Official assets protected', value: dashboard.summary.official_assets_protected, icon: Lock, accent: 'green' },
  ] : [];

  const pieData = useMemo(() => {
    if (!dashboard) return [];
    return Object.entries(dashboard.risk_distribution).map(([key, value]) => ({ name: key, value }));
  }, [dashboard]);

  const platformChartData = useMemo(() => {
    if (!dashboard) return [];
    return Object.entries(dashboard.platform_distribution).map(([name, value]) => ({ name, value }));
  }, [dashboard]);

  const lineChartData = useMemo(() => {
    if (!dashboard) return [];
    return dashboard.findings_by_month;
  }, [dashboard]);

  const filteredReportFindings = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    return (reportData?.findings || []).filter((finding) => !query || [
      finding.entity_name,
      finding.platform,
      finding.risk_level,
      String(finding.risk_score),
    ].some((value) => value.toLowerCase().includes(query)));
  }, [reportData, searchTerm]);

  const filteredDetections = useMemo(() => {
    return detections.filter((item) => {
      if (selectedTab === 'social' && item.entity_type !== 'social_profile') return false;
      if (selectedTab === 'apps' && item.entity_type !== 'application') return false;
      if (dashboardFilters.brand !== 'all' && String(item.brand_id) !== dashboardFilters.brand) return false;
      if (dashboardFilters.platform !== 'all' && item.platform !== dashboardFilters.platform) return false;
      if (dashboardFilters.risk !== 'all' && item.risk_level !== dashboardFilters.risk) return false;
      if (dashboardFilters.entity !== 'all' && item.entity_type !== dashboardFilters.entity) return false;
      if (dashboardFilters.status !== 'all' && item.status !== dashboardFilters.status) return false;
      const query = searchTerm.trim().toLowerCase();
      if (query && ![
        item.entity_name,
        item.entity_type,
        item.platform,
        item.risk_level,
        item.status,
        item.detection_reason,
        JSON.stringify(item.evidence || {}),
      ].some((value) => value.toLowerCase().includes(query))) return false;
      return true;
    });
  }, [detections, selectedTab, dashboardFilters, searchTerm]);

  const currentBrand = brands.find((brand) => brand.id === activeBrandId) || brands[0];

  const resetForm = () => {
    setBrandForm({
      id: '',
      name: '',
      company_description: '',
      industry: '',
      official_website: '',
      official_social_accounts: '',
      official_mobile_apps: '',
      official_package_ids: '',
      official_developer_names: '',
      brand_keywords: '',
      known_domains: '',
      additional_identifiers: '',
    });
  };

  const prepareForm = (brand: Brand) => {
    setActiveBrandId(brand.id);
    setBrandForm({
      id: String(brand.id),
      name: brand.name,
      company_description: brand.company_description,
      industry: brand.industry,
      official_website: brand.official_website,
      official_social_accounts: toInputValue(brand.official_social_accounts),
      official_mobile_apps: toInputValue(brand.official_mobile_apps),
      official_package_ids: toInputValue(brand.official_package_ids),
      official_developer_names: toInputValue(brand.official_developer_names),
      brand_keywords: toInputValue(brand.brand_keywords),
      known_domains: toInputValue(brand.known_domains),
      additional_identifiers: JSON.stringify(brand.additional_identifiers || {}),
    });
  };

  const handleBrandSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setActionError(null);
    const formData = new FormData();
    const fields = [
      ['name', brandForm.name],
      ['company_description', brandForm.company_description],
      ['industry', brandForm.industry],
      ['official_website', brandForm.official_website],
      ['official_social_accounts', JSON.stringify((brandForm.official_social_accounts || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['official_mobile_apps', JSON.stringify((brandForm.official_mobile_apps || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['official_package_ids', JSON.stringify((brandForm.official_package_ids || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['official_developer_names', JSON.stringify((brandForm.official_developer_names || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['brand_keywords', JSON.stringify((brandForm.brand_keywords || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['known_domains', JSON.stringify((brandForm.known_domains || '').split(',').map((value) => value.trim()).filter(Boolean))],
      ['additional_identifiers', brandForm.additional_identifiers || '{}'],
    ];
    fields.forEach(([key, value]) => formData.append(key, value));

    const logoInput = document.getElementById('brand-logo-upload') as HTMLInputElement | null;
    if (logoInput?.files?.length) {
      formData.append('logo', logoInput.files[0]);
    }

    const url = brandForm.id ? `/api/brands/${brandForm.id}` : '/api/brands';
    const method = brandForm.id ? 'PUT' : 'POST';
    try {
      const response = await apiFetch(url, { method, body: formData });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Brand could not be saved'));
      resetForm();
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Brand could not be saved.');
    }
  };

  const handleDeleteBrand = async (brandId: number) => {
    if (!window.confirm('Delete this brand and all local records?')) return;
    setActionError(null);
    try {
      const response = await apiFetch(`/api/brands/${brandId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Brand could not be deleted'));
      await fetchAll();
      if (brandId === activeBrandId) setActiveBrandId(null);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Brand could not be deleted.');
    }
  };

  const runDemoScan = async () => {
    setActionError(null);
    try {
      const response = await apiFetch('/api/run-demo-scan', { method: 'POST' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Demo scan failed'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Demo scan failed.');
    }
  };

  const addMonitoringSource = async (event: React.FormEvent, sourceType: string) => {
    event.preventDefault();
    if (!activeBrandId) return;
    setActionError(null);
    try {
      const response = await apiFetch('/api/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          brand_id: activeBrandId,
          source_type: sourceType,
          platform: sourceType === 'application' && !['Android', 'iOS'].includes(sourceForm.platform) ? 'Android' : sourceForm.platform,
          locator: sourceForm.locator,
        }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not add monitoring source'));
      setSourceForm({ platform: 'Instagram', locator: '' });
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not add monitoring source.');
    }
  };

  const removeMonitoringSource = async (sourceId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/sources/${sourceId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not remove monitoring source'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not remove monitoring source.');
    }
  };

  const addPhishTankSource = async () => {
    if (!activeBrandId) return;
    setActionError(null);
    try {
      const response = await apiFetch('/api/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          brand_id: activeBrandId,
          source_type: 'threat_feed',
          platform: 'PhishTank',
          locator: 'online-valid',
          interval_minutes: threatFeedInterval,
        }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not enable PhishTank monitoring'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not enable PhishTank monitoring.');
    }
  };

  const runThreatFeed = async (sourceId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/monitoring/sources/${sourceId}/run`, { method: 'POST' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'PhishTank monitoring failed'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'PhishTank monitoring failed.');
    }
  };

  const sendChatMessage = async (event: FormEvent) => {
    event.preventDefault();
    const message = chatInput.trim();
    if (!message || isChatSending) return;
    if (message.length > 4000) {
      setChatError('Messages must be 4,000 characters or fewer.');
      return;
    }

    setChatError(null);
    setChatInput('');
    setChatMessages((current) => [...current, { id: Date.now(), role: 'user', content: message }]);
    setIsChatSending(true);
    try {
      const response = await apiFetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      if (!response.ok) {
        const detail = await apiErrorMessage(response, 'AI Chat could not complete the request');
        if (response.status === 401 || response.status === 403) {
          throw new Error(`Authentication failed. Please sign in again. ${detail}`);
        }
        if (response.status === 429 || (response.status === 503 && /rate limit|quota/i.test(detail))) {
          throw new Error(`The AI service is rate-limited or its quota is exhausted. Please try again later. ${detail}`);
        }
        throw new Error(detail);
      }
      const result: { answer?: unknown } = await response.json();
      const answer = result.answer;
      if (typeof answer !== 'string' || !answer.trim()) {
        throw new Error('The AI service returned an empty or invalid response.');
      }
      setChatMessages((current) => [...current, { id: Date.now(), role: 'assistant', content: answer }]);
    } catch (error) {
      setChatError(error instanceof TypeError
        ? 'Could not connect to BRANDSHIELD AI. Check the backend connection and try again.'
        : error instanceof Error ? error.message : 'AI Chat failed. Please try again.');
    } finally {
      setIsChatSending(false);
    }
  };

  const clearChat = () => {
    if (isChatSending) return;
    setChatMessages([]);
    setChatError(null);
    setChatInput('');
  };

  const updateThreatFeedInterval = async (sourceId: number, intervalMinutes: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/sources/${sourceId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval_minutes: intervalMinutes }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not update monitoring schedule'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not update monitoring schedule.');
    }
  };

  const analyzeCandidate = async (event: React.FormEvent) => {
    event.preventDefault();
    setAnalysisError(null);
    setAnalysisResult(null);
    if (!activeBrandId) {
      setAnalysisError('Select a brand before submitting an analysis.');
      return;
    }
    const entityType = selectedTab === 'apps' ? 'application' : 'social_profile';
    setIsAnalyzing(true);
    try {
      const response = await apiFetch('/api/analysis/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...candidateForm, entity_type: entityType, brand_id: activeBrandId }),
      });
      const body = await response.clone().json().catch(() => ({}));
      if (!response.ok) {
        setAnalysisError(body.detail || `Analysis failed with HTTP ${response.status}.`);
        return;
      }
      setAnalysisResult(body as AnalysisResult);
      setCandidateForm({ name: '', url: '', description: '', entity_type: 'social_profile', platform: 'Instagram', package_id: '', developer_name: '' });
      await fetchAll();
    } catch (error) {
      setAnalysisError(error instanceof Error ? error.message : 'Could not reach the analysis service.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const createInvestigation = async (finding: Detection) => {
    setActionError(null);
    try {
      const response = await apiFetch('/api/investigations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          brand_id: finding.brand_id,
          title: `Review ${finding.entity_name}`,
          summary: finding.detection_reason,
          risk_level: finding.risk_level,
          detection_id: finding.id,
        }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not create investigation'));
      await fetchAll();
      setSelectedTab('investigations');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not create investigation.');
    }
  };

  const changeFindingStatus = async (findingId: number, status: string) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/detections/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not update finding status'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not update finding status.');
    }
  };

  const deleteFinding = async (findingId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/detections/${findingId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not delete finding'));
      if (findingDetails?.id === findingId) setFindingDetails(null);
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not delete finding.');
    }
  };

  const viewFindingDetails = async (findingId: number) => {
    if (findingDetails?.id === findingId) {
      setFindingDetails(null);
      return;
    }
    setLoadingFindingId(findingId);
    setActionError(null);
    try {
      const response = await apiFetch(`/api/detections/${findingId}`);
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not load finding details'));
      setFindingDetails(await response.json() as FindingDetails);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not load finding details.');
    } finally {
      setLoadingFindingId(null);
    }
  };

  const saveInvestigation = async (investigationId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/investigations/${investigationId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(investigationDraft),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not update investigation'));
      setEditingInvestigationId(null);
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not update investigation.');
    }
  };

  const deleteInvestigation = async (investigationId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/investigations/${investigationId}`, { method: 'DELETE' });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not delete investigation'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not delete investigation.');
    }
  };

  const setInvestigationStatus = async (investigationId: number, status: string) => {
    const body = new FormData();
    body.append('status', status);
    setActionError(null);
    try {
      const response = await apiFetch(`/api/investigations/${investigationId}`, { method: 'PATCH', body });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not update investigation'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not update investigation.');
    }
  };

  const exportReport = async () => {
    setActionError(null);
    try {
      const response = await apiFetch('/api/reports/export.csv');
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not export report'));
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'brandshield-findings.csv';
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not export report.');
    }
  };

  const submitCustomerReport = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const screenshot = formData.get('screenshot') as File | null;
    const fileData = new FormData();
    if (screenshot?.size) fileData.append('screenshot', screenshot);
    const brandId = formData.get('brand_id')?.toString() || '';
    const reportText = formData.get('report_text')?.toString() || '';
    const reportedUrl = formData.get('reported_url')?.toString() || '';
    const reporterContact = formData.get('reporter_contact')?.toString() || '';
    if (!screenshot?.size && reportText.trim().length < 5) {
      setUploadMessage('Enter at least five characters of report text or attach a screenshot.');
      return;
    }
    let response: Response;
    setIsSubmittingReport(true);
    setCustomerReportResult(null);
    try {
      if (screenshot?.size) {
        if (brandId) fileData.append('brand_id', brandId);
        fileData.append('report_text', reportText);
        fileData.append('reported_url', reportedUrl);
        fileData.append('reporter_contact', reporterContact);
        response = await apiFetch('/api/customer/reports/screenshot', { method: 'POST', body: fileData });
      } else {
        response = await apiFetch('/api/customer/reports', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            brand_id: brandId ? Number(brandId) : null,
            report_text: reportText,
            reported_url: reportedUrl,
            reporter_contact: reporterContact,
          }),
        });
      }
      const body = await response.clone().json().catch(() => ({}));
      if (!response.ok) {
        setUploadMessage(body.detail || `Report submission failed with HTTP ${response.status}.`);
        return;
      }
      setCustomerReportResult(body);
      setUploadMessage(body.status === 'duplicate'
        ? 'This report resembles an earlier submission and was recorded as a possible duplicate for analyst review.'
        : 'Report received. It will be reviewed by a brand analyst.');
      form.reset();
      await fetchAll();
    } catch (error) {
      setUploadMessage(error instanceof Error ? error.message : 'Could not reach the report service.');
    } finally {
      setIsSubmittingReport(false);
    }
  };

  const reviewCommunityReport = async (reportId: number, status: string, analystVerified: boolean) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/community/reports/${reportId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, analyst_verified: analystVerified }),
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Could not save report review'));
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not save report review.');
    }
  };

  const analyzeQrImage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setQrError(null);
    setQrResult(null);
    const formData = new FormData(event.currentTarget);
    if (activeBrandId) formData.set('brand_id', String(activeBrandId));
    setIsQrAnalyzing(true);
    try {
      const response = await apiFetch('/api/qr/analyze', { method: 'POST', body: formData });
      const body = await response.clone().json().catch(() => ({}));
      if (!response.ok) {
        setQrError(body.detail || `QR analysis failed with HTTP ${response.status}.`);
        return;
      }
      setQrResult(body);
      setUploadMessage('');
      if (body.stored) await fetchAll();
    } catch (error) {
      setQrError(error instanceof Error ? error.message : 'Could not reach the QR analysis service.');
    } finally {
      setIsQrAnalyzing(false);
    }
  };

  const importFindingsCsv = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !activeBrandId) return;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('brand_id', String(activeBrandId));
    setActionError(null);
    try {
      const response = await apiFetch('/api/ingestion/csv', { method: 'POST', body: formData });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'CSV import failed'));
      const body = await response.json();
      setUploadMessage(`Imported and analyzed ${body.imported} candidate records.`);
      event.target.value = '';
      await fetchAll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'CSV import failed.');
    }
  };

  const loadCopilotGuidance = async (investigationId: number) => {
    setActionError(null);
    try {
      const response = await apiFetch(`/api/investigations/${investigationId}/copilot`);
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Investigation guidance could not be generated'));
      setCopilotResult(await response.json());
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Investigation guidance could not be generated.');
    }
  };

  const renderOverview = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-300/90">Threat posture</p>
          <h2 className="mt-2 text-3xl font-semibold text-white">Digital Risk Protection Overview</h2>
        </div>
        <button onClick={runDemoScan} className="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 shadow-glow hover:bg-cyan-400">Run Demo Scan</button>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4">
        <div className="grid gap-3 md:grid-cols-5">
          <select value={dashboardFilters.brand} onChange={(e) => setDashboardFilters({ ...dashboardFilters, brand: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
            <option value="all">All brands</option>
            {brands.map((brand) => <option key={brand.id} value={String(brand.id)}>{brand.name}</option>)}
          </select>
          <select value={dashboardFilters.platform} onChange={(e) => setDashboardFilters({ ...dashboardFilters, platform: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
            <option value="all">All platforms</option>
            {[...new Set(detections.map((item) => item.platform))].map((platform) => <option key={platform} value={platform}>{platform}</option>)}
          </select>
          <select value={dashboardFilters.risk} onChange={(e) => setDashboardFilters({ ...dashboardFilters, risk: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
            <option value="all">All risk levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={dashboardFilters.entity} onChange={(e) => setDashboardFilters({ ...dashboardFilters, entity: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
            <option value="all">All entity types</option>
            <option value="social_profile">Social profile</option>
            <option value="application">Application</option>
          </select>
          <select value={dashboardFilters.status} onChange={(e) => setDashboardFilters({ ...dashboardFilters, status: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="review">Review</option>
            <option value="monitoring">Monitoring</option>
          </select>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {summaryCards.map((card) => (
          <div key={card.label} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg shadow-slate-950/20">
            <div className="flex items-center justify-between">
              <div className="rounded-xl bg-slate-800 p-2 text-cyan-300">
                <card.icon className="h-5 w-5" />
              </div>
              <span className="text-xs uppercase tracking-[0.2em] text-slate-400">Live</span>
            </div>
            <div className="mt-5 text-3xl font-bold text-white">{card.value}</div>
            <div className="mt-2 text-sm text-slate-400">{card.label}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Threats by platform</h3>
            <BarChart3 className="h-5 w-5 text-cyan-300" />
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={platformChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="value" fill="#67e8f9" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Risk-level distribution</h3>
            <TrendingUp className="h-5 w-5 text-violet-300" />
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={90} innerRadius={45} paddingAngle={2}>
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={riskColors[entry.name as RiskLevel] || '#67e8f9'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <h3 className="mb-4 text-lg font-semibold text-white">Findings over time</h3>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={lineChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Line type="monotone" dataKey="value" stroke="#8b5cf6" strokeWidth={3} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <h3 className="mb-4 text-lg font-semibold text-white">Social vs app threats</h3>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-xl bg-slate-800 p-4">
              <div className="text-sm text-slate-400">Social</div>
              <div className="mt-2 text-3xl font-bold text-cyan-300">{dashboard?.summary.social_profiles_analyzed ?? 0}</div>
            </div>
            <div className="rounded-xl bg-slate-800 p-4">
              <div className="text-sm text-slate-400">Applications</div>
              <div className="mt-2 text-3xl font-bold text-violet-300">{dashboard?.summary.applications_analyzed ?? 0}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Recent detections</h3>
          <span className="text-xs uppercase tracking-[0.2em] text-slate-400">Simulated demo data</span>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-3 pr-4">Entity</th>
                <th className="pb-3 pr-4">Type</th>
                <th className="pb-3 pr-4">Platform</th>
                <th className="pb-3 pr-4">Similarity</th>
                <th className="pb-3 pr-4">Risk</th>
                <th className="pb-3 pr-4">Risk Level</th>
                <th className="pb-3 pr-4">Reason</th>
                <th className="pb-3 pr-4">Status</th>
                <th className="pb-3 pr-4">Detected</th>
              </tr>
            </thead>
            <tbody>
              {filteredDetections.slice(0, 8).map((item) => (
                <tr key={item.id} className="border-t border-slate-800 text-slate-200">
                  <td className="py-3 pr-4">{item.entity_name}</td>
                  <td className="py-3 pr-4">{item.entity_type}</td>
                  <td className="py-3 pr-4">{item.platform}</td>
                  <td className="py-3 pr-4">{item.similarity_score}%</td>
                  <td className="py-3 pr-4">{item.risk_score}</td>
                  <td className="py-3 pr-4"><span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(item.risk_level)}`}>{item.risk_level}</span></td>
                  <td className="py-3 pr-4 text-slate-300">{item.detection_reason}</td>
                  <td className="py-3 pr-4"><span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(item.status)}`}>{item.status}</span></td>
                  <td className="py-3 pr-4 text-slate-400">{new Date(item.detected_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderBrandProfiles = () => (
    <div className="grid gap-6 xl:grid-cols-[1.1fr,0.9fr]">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Brand registry</h3>
          <button onClick={() => resetForm()} className="rounded-xl border border-slate-700 px-3 py-2 text-sm text-slate-200">New profile</button>
        </div>
        <div className="space-y-4">
          {brands.map((brand) => (
            <div key={brand.id} className="rounded-xl border border-slate-800 bg-slate-950/80 p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300">
                    {brand.name[0] || 'B'}
                  </div>
                  <div>
                    <div className="font-medium text-white">{brand.name}</div>
                    <div className="text-xs text-slate-400">{brand.industry || 'Unspecified industry'}</div>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => prepareForm(brand)} className="rounded-lg bg-slate-800 p-2 text-slate-200"><Pencil className="h-4 w-4" /></button>
                  <button onClick={() => handleDeleteBrand(brand.id)} className="rounded-lg bg-red-500/10 p-2 text-red-300"><Trash2 className="h-4 w-4" /></button>
                </div>
              </div>
              <p className="mt-3 text-sm text-slate-300">{brand.company_description || 'No description yet.'}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {(brand.brand_keywords || []).slice(0, 5).map((keyword) => (
                  <span key={keyword} className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-300">{keyword}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <form onSubmit={handleBrandSubmit} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="mb-4 text-lg font-semibold text-white">{brandForm.id ? 'Edit brand' : 'Create brand profile'}</h3>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Brand name</span>
            <input value={brandForm.name} onChange={(e) => setBrandForm({ ...brandForm, name: e.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" required />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Company description</span>
            <textarea value={brandForm.company_description} onChange={(e) => setBrandForm({ ...brandForm, company_description: e.target.value })} rows={3} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label>
            <span className="mb-2 block text-sm text-slate-300">Industry</span>
            <input value={brandForm.industry} onChange={(e) => setBrandForm({ ...brandForm, industry: e.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label>
            <span className="mb-2 block text-sm text-slate-300">Official website</span>
            <input value={brandForm.official_website} onChange={(e) => setBrandForm({ ...brandForm, official_website: e.target.value })} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Official social accounts</span>
            <input value={brandForm.official_social_accounts} onChange={(e) => setBrandForm({ ...brandForm, official_social_accounts: e.target.value })} placeholder="https://instagram.com/example, https://x.com/example" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Official mobile apps</span>
            <input value={brandForm.official_mobile_apps} onChange={(e) => setBrandForm({ ...brandForm, official_mobile_apps: e.target.value })} placeholder="App Name One, App Name Two" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Package IDs</span>
            <input value={brandForm.official_package_ids} onChange={(e) => setBrandForm({ ...brandForm, official_package_ids: e.target.value })} placeholder="com.example.app, com.example.wallet" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Developer names</span>
            <input value={brandForm.official_developer_names} onChange={(e) => setBrandForm({ ...brandForm, official_developer_names: e.target.value })} placeholder="Example Labs, Example Group" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Brand keywords</span>
            <input value={brandForm.brand_keywords} onChange={(e) => setBrandForm({ ...brandForm, brand_keywords: e.target.value })} placeholder="secure, wallet, identity" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Known domains</span>
            <input value={brandForm.known_domains} onChange={(e) => setBrandForm({ ...brandForm, known_domains: e.target.value })} placeholder="example.com, wallet.example.com" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Logo upload</span>
            <input id="brand-logo-upload" type="file" accept="image/png,image/jpeg,image/webp" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-200" />
            <span className="mt-2 block text-xs text-slate-400">PNG, JPG, JPEG, and WEBP up to 5MB. Logo hashes are generated locally for matching.</span>
          </label>
          <label className="md:col-span-2">
            <span className="mb-2 block text-sm text-slate-300">Additional identifiers (JSON)</span>
            <textarea value={brandForm.additional_identifiers} onChange={(e) => setBrandForm({ ...brandForm, additional_identifiers: e.target.value })} rows={2} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
          </label>
        </div>
        <div className="mt-6 flex gap-3">
          <button type="submit" className="rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950">{brandForm.id ? 'Save changes' : 'Create brand'}</button>
          <button type="button" onClick={resetForm} className="rounded-xl border border-slate-700 px-4 py-2 text-slate-200">Clear</button>
        </div>
      </form>
    </div>
  );

  const renderMonitoring = (entityType: 'social_profile' | 'application') => {
    const visibleDetections = filteredDetections.filter((item) =>
      item.entity_type === entityType ||
      (entityType === 'social_profile' && item.entity_type === 'domain' && item.platform === 'PhishTank'),
    );
    return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-800 bg-slate-900/80 p-4">
        <div><h3 className="font-medium text-white">Bulk candidate ingestion</h3><p className="text-xs text-slate-400">Import a CSV with name and optional URL, platform, and description columns.</p></div>
        <label className="cursor-pointer rounded-xl border border-cyan-500/40 px-4 py-2 text-sm text-cyan-200">Import CSV<input type="file" accept=".csv,text/csv" onChange={importFindingsCsv} className="hidden" /></label>
        {uploadMessage && <p role="status" className="w-full text-sm text-cyan-200">{uploadMessage}</p>}
      </div>
      <div className="grid gap-6 xl:grid-cols-[0.9fr,1.1fr]">
        <form onSubmit={analyzeCandidate} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <h3 className="text-lg font-semibold text-white">Analyze a candidate</h3>
          <p className="mt-1 text-sm text-slate-400">Local analysis only; candidate details are stored in your SQLite database.</p>
          <div className="mt-4 grid gap-3">
            <input value={candidateForm.name} onChange={(e) => setCandidateForm({ ...candidateForm, name: e.target.value })} placeholder={`${entityType === 'social_profile' ? 'Account or page name' : 'Application name'} (optional if text or URL is provided)`} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
            <select value={candidateForm.platform} onChange={(e) => setCandidateForm({ ...candidateForm, platform: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white">
              {(entityType === 'social_profile' ? ['Instagram', 'Facebook', 'X', 'LinkedIn', 'TikTok', 'YouTube'] : ['Android', 'iOS']).map((platform) => <option key={platform}>{platform}</option>)}
            </select>
            <input value={candidateForm.url} onChange={(e) => setCandidateForm({ ...candidateForm, url: e.target.value })} placeholder="Profile / listing URL or domain" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
            {entityType === 'application' && <>
              <input value={candidateForm.package_id} onChange={(e) => setCandidateForm({ ...candidateForm, package_id: e.target.value })} placeholder="Package ID (optional)" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
              <input value={candidateForm.developer_name} onChange={(e) => setCandidateForm({ ...candidateForm, developer_name: e.target.value })} placeholder="Developer / publisher (optional)" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
            </>}
            <textarea value={candidateForm.description} onChange={(e) => setCandidateForm({ ...candidateForm, description: e.target.value })} rows={3} placeholder="Description or listing copy" className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
            <button type="submit" disabled={isAnalyzing} className="rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950 disabled:cursor-wait disabled:opacity-60">{isAnalyzing ? 'Analyzing…' : 'Analyze locally'}</button>
            {analysisError && <p role="alert" className="rounded-xl border border-red-500/30 bg-red-950/30 p-3 text-sm text-red-200">{analysisError}</p>}
            {analysisResult && (
              <section aria-live="polite" className="space-y-3 rounded-xl border border-cyan-500/30 bg-slate-950/80 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h4 className="font-semibold text-white">Analysis result · {analysisResult.entity_name}</h4>
                  <span className={`rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(analysisResult.risk_level)}`}>
                    {analysisResult.risk_category.replace('_', ' ')} · {analysisResult.risk_score}/100
                  </span>
                </div>
                <p className="text-sm text-slate-300">{analysisResult.explanation}</p>
                {analysisResult.url && <p className="break-all text-xs text-cyan-200">Analyzed without opening: {analysisResult.url}</p>}
                {analysisResult.indicators.length > 0 ? (
                  <ul className="list-inside list-disc space-y-1 text-sm text-amber-200">
                    {analysisResult.indicators.map((indicator, index) => <li key={`${indicator.code}-${index}`}>{indicator.message}</li>)}
                  </ul>
                ) : <p className="text-sm text-slate-400">No detected indicators.</p>}
                <details className="text-sm text-slate-300">
                  <summary className="cursor-pointer text-cyan-200">Evidence details</summary>
                  <ul className="mt-2 list-inside list-disc space-y-1">
                    {analysisResult.evidence.map((item, index) => <li key={`${item.type}-${index}`}>{item.value}</li>)}
                  </ul>
                </details>
                <p className="text-xs text-slate-500">Heuristic assessment only; suspicious results are not confirmation of fraud.</p>
              </section>
            )}
          </div>
        </form>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <h3 className="text-lg font-semibold text-white">Configured monitoring sources</h3>
          <form onSubmit={(event) => addMonitoringSource(event, entityType)} className="mt-4 flex flex-col gap-3 sm:flex-row">
            <select value={sourceForm.platform} onChange={(e) => setSourceForm({ ...sourceForm, platform: e.target.value })} className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white">
              {(entityType === 'social_profile' ? ['Instagram', 'Facebook', 'X', 'LinkedIn', 'TikTok', 'YouTube'] : ['Android', 'iOS']).map((platform) => <option key={platform}>{platform}</option>)}
            </select>
            <input required value={sourceForm.locator} onChange={(e) => setSourceForm({ ...sourceForm, locator: e.target.value })} placeholder="Profile URL / app name / package ID" className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
            <button type="submit" className="rounded-xl border border-cyan-500/40 px-4 py-2 text-cyan-200">Add source</button>
          </form>
          <div className="mt-4 space-y-2">
            {sources.filter((source) => source.source_type === entityType && source.brand_id === activeBrandId).map((source) => (
              <div key={source.id} className="flex items-center justify-between gap-3 rounded-xl bg-slate-950/70 p-3 text-sm">
                <div><div className="text-slate-200">{source.locator}</div><div className="text-xs text-slate-500">{source.platform} · locally configured</div></div>
                <button onClick={() => removeMonitoringSource(source.id)} className="text-xs text-red-300">Remove</button>
              </div>
            ))}
            {!sources.some((source) => source.source_type === entityType && source.brand_id === activeBrandId) && <p className="text-sm text-slate-400">No sources configured for this brand.</p>}
          </div>
          {entityType === 'social_profile' && <section className="mt-5 border-t border-slate-800 pt-5" aria-label="Website threat feed monitoring">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h4 className="font-semibold text-white">Website and domain threat feed</h4>
                <p className="mt-1 text-xs text-slate-400">Checks PhishTank’s verified-active feed. Indicator URLs are analyzed as data and never opened.</p>
              </div>
              <button type="button" onClick={addPhishTankSource} disabled={!activeBrandId || sources.some((source) => source.source_type === 'threat_feed' && source.brand_id === activeBrandId)} className="rounded-xl border border-cyan-500/40 px-3 py-2 text-sm text-cyan-200 disabled:opacity-50">Enable PhishTank</button>
            </div>
            <label className="mt-3 flex items-center gap-2 text-xs text-slate-400">
              Run interval
              <select value={threatFeedInterval} onChange={(event) => setThreatFeedInterval(Number(event.target.value))} className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
                <option value={60}>Every hour</option>
                <option value={360}>Every 6 hours</option>
                <option value={720}>Every 12 hours</option>
                <option value={1440}>Daily</option>
              </select>
            </label>
            <div className="mt-3 space-y-2">
              {sources.filter((source) => source.source_type === 'threat_feed' && source.brand_id === activeBrandId).map((source) => (
                <div key={source.id} className="rounded-xl bg-slate-950/70 p-3 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <span className={`rounded-full border px-2 py-1 text-xs ${source.status === 'LIVE' ? 'border-green-500/30 text-green-300' : source.status === 'ERROR' ? 'border-red-500/30 text-red-300' : 'border-amber-500/30 text-amber-200'}`}>{source.status}</span>
                      <span className="ml-2 text-slate-300">PhishTank · {source.locator}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <select aria-label="PhishTank monitoring interval" value={source.interval_minutes} onChange={(event) => void updateThreatFeedInterval(source.id, Number(event.target.value))} className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200">
                        <option value={60}>Hourly</option>
                        <option value={360}>Every 6 hours</option>
                        <option value={720}>Every 12 hours</option>
                        <option value={1440}>Daily</option>
                      </select>
                      <button type="button" onClick={() => void runThreatFeed(source.id)} className="rounded-lg border border-cyan-500/40 px-3 py-1.5 text-xs text-cyan-200">Run now</button>
                      <button type="button" onClick={() => void removeMonitoringSource(source.id)} className="text-xs text-red-300">Remove</button>
                    </div>
                  </div>
                  {source.last_checked_at && <p className="mt-2 text-xs text-slate-500">Last checked: {new Date(source.last_checked_at).toLocaleString()}</p>}
                  {source.last_error && <p role="status" className="mt-2 text-xs text-amber-200">{source.last_error}</p>}
                  {source.status === 'CONFIGURATION REQUIRED' && <p className="mt-2 text-xs text-amber-200">Set PHISHTANK_API_KEY in the local .env file and restart the backend. The key is never displayed in the app.</p>}
                </div>
              ))}
            </div>
          </section>}
        </div>
      </div>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="mb-4 text-lg font-semibold text-white">{entityType === 'social_profile' ? 'Social profile and PhishTank domain findings' : 'Mobile application findings'}</h3>
        <div className="space-y-4">
          {visibleDetections.map((item) => (
            <div key={item.id} className="rounded-xl border border-slate-800 bg-slate-950/80 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div><div className="text-base font-medium text-white">{item.entity_name}</div><div className="text-xs text-slate-400">{item.platform}</div></div>
                <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(item.risk_level)}`}>{item.risk_level}</span>
              </div>
              <div className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-3">
                <div><span className="text-slate-400">Similarity:</span> {item.similarity_score}%</div>
                <div><span className="text-slate-400">Risk score:</span> {item.risk_score}</div>
                <div><span className="text-slate-400">Status:</span> {item.status}</div>
              </div>
              <p className="mt-3 text-sm text-slate-300">{item.detection_reason}</p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <label className="text-xs text-slate-400">Finding status
                  <select aria-label={`Finding status for ${item.entity_name}`} value={item.status} onChange={(event) => changeFindingStatus(item.id, event.target.value)} className="ml-2 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
                    {['open', 'review', 'monitoring', 'resolved', 'closed'].map((status) => <option key={status}>{status}</option>)}
                  </select>
                </label>
                <button onClick={() => void viewFindingDetails(item.id)} disabled={loadingFindingId === item.id} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-50">{loadingFindingId === item.id ? 'Loading…' : findingDetails?.id === item.id ? 'Hide evidence' : 'View evidence'}</button>
                <button onClick={() => createInvestigation(item)} className="rounded-lg border border-cyan-500/40 px-3 py-1.5 text-xs text-cyan-200">Open investigation</button>
                <button onClick={() => deleteFinding(item.id)} className="rounded-lg border border-red-500/30 px-3 py-1.5 text-xs text-red-200">Delete finding</button>
              </div>
              {findingDetails?.id === item.id && <section aria-label={`Evidence for ${item.entity_name}`} className="mt-4 rounded-xl border border-slate-700 bg-slate-900/70 p-4">
                <h4 className="font-medium text-white">Stored evidence</h4>
                <p className="mt-1 text-xs text-slate-400">Finding #{findingDetails.id} · {brands.find((brand) => brand.id === findingDetails.brand_id)?.name || `Brand #${findingDetails.brand_id}`} · {findingDetails.investigation_ids.length} linked investigations</p>
                {findingDetails.evidence_records.length > 0 ? <ul className="mt-3 space-y-2">{findingDetails.evidence_records.map((evidence) => (
                  <li key={evidence.id} className="rounded-lg bg-slate-950/80 p-3 text-sm text-slate-300">
                    <div className="flex justify-between gap-3"><strong>{evidence.type}</strong><span className="text-xs text-slate-400">Confidence {evidence.confidence}%</span></div>
                    <p className="mt-1 break-words">{evidence.value}</p>
                  </li>
                ))}</ul> : <p className="mt-2 text-sm text-slate-400">No evidence records are stored for this finding.</p>}
              </section>}
            </div>
          ))}
          {visibleDetections.length === 0 && <p className="rounded-xl bg-slate-950/70 p-4 text-sm text-slate-400">No findings match this view.</p>}
        </div>
      </div>
    </div>
    );
  };

  const renderScamDna = () => {
    const graphNodes = graphData.nodes;
    const nodePositions = new Map(graphNodes.map((node, index) => [
      node.id,
      { x: 70 + (index % 4) * 205, y: 45 + Math.floor(index / 4) * 83 },
    ]));
    const graphHeight = Math.max(340, Math.ceil(graphNodes.length / 4) * 83 + 20);
    const graphNodesById = new Map(graphNodes.map((node) => [node.id, node]));
    const selectedGraphNode = graphNodesById.get(selectedGraphNodeId || '');
    const selectedGraphEdges = selectedGraphNode
      ? graphData.edges.filter((edge) => edge.source === selectedGraphNode.id || edge.target === selectedGraphNode.id)
      : [];
    return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="flex items-center justify-between">
          <div><h3 className="text-lg font-semibold text-white">Evidence-linked Scam DNA graph</h3><p className="mt-1 text-sm text-slate-400">Select a node to inspect its stored details and evidence-backed connections. Similarity alone does not prove common ownership.</p></div>
          <span className="text-xs text-cyan-200">{graphData.nodes.length} nodes · {graphData.edges.length} links</span>
        </div>
        {graphNodes.length === 0 ? (
          <p className="mt-4 rounded-xl bg-slate-950/70 p-5 text-sm text-slate-400">No graph records are available for this organization yet.</p>
        ) : <div className="mt-4 overflow-auto">
          <svg viewBox={`0 0 850 ${graphHeight}`} role="img" aria-label="Threat entities connected to brand and evidence" className="min-w-[720px] w-full rounded-xl bg-slate-950/70">
            {graphData.edges.map((edge, index) => {
              const source = nodePositions.get(edge.source);
              const target = nodePositions.get(edge.target);
              if (!source || !target) return null;
              return <line key={`${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="#334155" strokeWidth="2" />;
            })}
            {graphNodes.map((node) => {
              const position = nodePositions.get(node.id)!;
              const color = node.kind === 'brand' ? '#67e8f9' : node.kind === 'evidence' ? '#a78bfa' : riskColors[node.risk as RiskLevel] || '#f59e0b';
              return <g key={node.id}>
                <circle
                  cx={position.x}
                  cy={position.y}
                  r="11"
                  fill={color}
                  fillOpacity={0.9}
                  stroke={selectedGraphNodeId === node.id ? '#ffffff' : 'transparent'}
                  strokeWidth="3"
                />
                <text
                  x={position.x + 17}
                  y={position.y + 4}
                  fill="#e2e8f0"
                  fontSize="11"
                  role="button"
                  tabIndex={0}
                  aria-label={`Select ${node.kind}: ${node.label}`}
                  onClick={() => setSelectedGraphNodeId(node.id)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setSelectedGraphNodeId(node.id);
                    }
                  }}
                  className="cursor-pointer focus:outline-none"
                >{String(node.label || node.kind).slice(0, 22)}</text>
              </g>;
            })}
          </svg>
        </div>}
        {selectedGraphNode && <section aria-label="Selected graph node details" className="mt-4 rounded-xl border border-slate-700 bg-slate-950/70 p-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h4 className="font-semibold text-white">{selectedGraphNode.label}</h4>
            <span className="text-xs uppercase tracking-wide text-cyan-200">{selectedGraphNode.kind.replace('_', ' ')}</span>
          </div>
          <dl className="mt-3 grid gap-2 text-sm text-slate-300 sm:grid-cols-2">
            {(['risk', 'risk_score', 'platform', 'status', 'value', 'decoded_url', 'reported_url', 'official_website', 'campaign_key', 'canonical_key', 'detected_at', 'created_at', 'detection_reason', 'report_text'] as const)
              .filter((key) => selectedGraphNode[key] !== undefined && selectedGraphNode[key] !== null && selectedGraphNode[key] !== '')
              .map((key) => <div key={key} className={['detection_reason', 'report_text'].includes(key) ? 'sm:col-span-2' : ''}><dt className="inline text-slate-500">{key.replaceAll('_', ' ')}: </dt><dd className="inline break-all">{String(selectedGraphNode[key])}</dd></div>)}
          </dl>
          <h5 className="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">Stored relationships ({selectedGraphEdges.length})</h5>
          {selectedGraphEdges.length ? <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {selectedGraphEdges.map((edge, index) => {
              const neighborId = edge.source === selectedGraphNode.id ? edge.target : edge.source;
              const neighbor = graphNodesById.get(neighborId);
              const evidenceId = edge.evidence_id;
              return <li key={`${edge.source}-${edge.target}-${index}`} className="rounded-lg bg-slate-900 p-2">
                <span className="text-cyan-200">{edge.relation.replaceAll('_', ' ')}</span>
                <span> → {neighbor?.label || neighborId}</span>
                {edge.confidence !== undefined && <span className="ml-2 text-xs text-slate-500">score {Math.round(Number(edge.confidence) * 100)}%</span>}
                {evidenceId !== undefined && evidenceId !== null && <span className="ml-2 text-xs text-violet-200">Evidence #{String(evidenceId)}</span>}
                {edge.analyst_verified === true && <span className="ml-2 text-xs text-green-200">analyst verified</span>}
                {typeof edge.summary === 'string' && <p className="mt-1 text-xs text-slate-400">{edge.summary}</p>}
              </li>;
            })}
          </ul> : <p className="mt-2 text-sm text-slate-500">No stored relationships are attached to this node.</p>}
        </section>}
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">Risk explanations</h3>
        <div className="mt-6 space-y-4">
          {detections.slice(0, 5).map((item) => (
            <div key={item.id} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="text-sm text-slate-400">{item.entity_name}</div>
              <div className="mt-2 text-slate-200">{item.detection_reason}</div>
              <div className="mt-3 text-xs uppercase tracking-[0.2em] text-violet-300">Confidence {Math.min(99, Math.round((item.similarity_score + item.risk_score) / 2))}%</div>
            </div>
          ))}
        </div>
      </div>
    </div>
    </div>
    );
  };

  const renderInvestigations = () => (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
      <h3 className="mb-4 text-lg font-semibold text-white">Threat investigation center</h3>
      <div className="space-y-4">
        {investigations.map((inv) => (
          <div key={inv.id} className="rounded-xl border border-slate-800 bg-slate-950/80 p-4">
            {editingInvestigationId === inv.id ? <div className="space-y-3">
              <input aria-label="Investigation title" value={investigationDraft.title} onChange={(event) => setInvestigationDraft({ ...investigationDraft, title: event.target.value })} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white" />
              <textarea aria-label="Investigation summary" value={investigationDraft.summary} onChange={(event) => setInvestigationDraft({ ...investigationDraft, summary: event.target.value })} rows={3} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white" />
              <select aria-label="Investigation risk level" value={investigationDraft.risk_level} onChange={(event) => setInvestigationDraft({ ...investigationDraft, risk_level: event.target.value })} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white">
                {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map((level) => <option key={level}>{level}</option>)}
              </select>
              <select aria-label="Linked finding" value={investigationDraft.detection_id ?? ''} onChange={(event) => setInvestigationDraft({ ...investigationDraft, detection_id: event.target.value ? Number(event.target.value) : null })} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white">
                <option value="">No linked finding</option>
                {detections.filter((finding) => finding.brand_id === inv.brand_id).map((finding) => <option key={finding.id} value={finding.id}>Finding #{finding.id} · {finding.entity_name}</option>)}
              </select>
              <div className="flex gap-2">
                <button onClick={() => saveInvestigation(inv.id)} className="rounded-lg border border-cyan-500/40 px-3 py-2 text-xs text-cyan-200">Save changes</button>
                <button onClick={() => setEditingInvestigationId(null)} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300">Cancel</button>
              </div>
            </div> : <>
              <div className="flex items-center justify-between gap-3">
                <div className="font-medium text-white">{inv.title}</div>
                <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(inv.risk_level)}`}>{inv.risk_level}</span>
              </div>
              <p className="mt-3 text-sm text-slate-300">{inv.summary}</p>
            </>}
            <div className="mt-2 text-xs text-slate-400">Brand: {brands.find((brand) => brand.id === inv.brand_id)?.name || `Brand #${inv.brand_id}`}</div>
            <div className="mt-1 text-xs text-slate-400">{inv.detection_id ? `Linked finding #${inv.detection_id}: ${detections.find((item) => item.id === inv.detection_id)?.entity_name || 'finding unavailable'}` : 'No finding currently linked'}</div>
            <div className="mt-3 flex items-center justify-between text-xs uppercase tracking-[0.2em] text-slate-400">
              <select aria-label={`Status for ${inv.title}`} value={inv.status} onChange={(event) => setInvestigationStatus(inv.id, event.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
                {['open', 'investigating', 'resolved', 'closed'].map((status) => <option key={status}>{status}</option>)}
              </select>
              <span>{new Date(inv.created_at).toLocaleDateString()}</span>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button onClick={() => loadCopilotGuidance(inv.id)} className="rounded-lg border border-violet-500/40 px-3 py-2 text-xs text-violet-200">Investigation Copilot</button>
              <button onClick={() => { setEditingInvestigationId(inv.id); setInvestigationDraft({ title: inv.title, summary: inv.summary, risk_level: inv.risk_level, detection_id: inv.detection_id }); }} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200">Edit investigation</button>
              <button onClick={() => deleteInvestigation(inv.id)} className="rounded-lg border border-red-500/30 px-3 py-2 text-xs text-red-200">Delete investigation</button>
            </div>
          </div>
        ))}
        {investigations.length === 0 && <p className="rounded-xl bg-slate-950/70 p-4 text-sm text-slate-400">No investigations are available for this organization.</p>}
      </div>
      {copilotResult && <div className="mt-5 rounded-xl border border-violet-500/30 bg-violet-950/20 p-4">
        <h4 className="font-semibold text-white">Local investigation guidance</h4>
        <p className="mt-2 text-sm text-slate-300">{copilotResult.summary}</p>
        <p className="mt-2 text-xs text-amber-200">{copilotResult.disclaimer}</p>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-slate-300">{copilotResult.suggested_steps?.map((step: string) => <li key={step}>{step}</li>)}</ol>
      </div>}
    </div>
  );

  const renderCampaigns = () => (
    <div className="space-y-5">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">Scam campaign evolution</h3>
        <p className="mt-1 text-sm text-slate-400">Timeline entries are grouped from analyzed findings and linked evidence. Similarity is not proof of common ownership.</p>
      </div>
      {campaigns.map((campaign) => (
        <article key={campaign.id} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold text-white">{campaign.title}</h3><span className="rounded-full bg-cyan-500/10 px-3 py-1 text-xs text-cyan-200">{campaign.status}</span></div>
          <p className="mt-1 text-xs text-slate-500">Campaign key: {campaign.campaign_key}</p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-300">
            <span className="rounded-lg bg-slate-800 px-2 py-1">{campaign.event_count} timeline events</span>
            <span className="rounded-lg bg-slate-800 px-2 py-1">{campaign.linked_finding_count} current findings</span>
            {(['critical', 'high', 'medium', 'low'] as const).filter((level) => campaign.risk_summary[level] > 0).map((level) => (
              <span key={level} className="rounded-lg bg-slate-800 px-2 py-1">{campaign.risk_summary[level]} {level}</span>
            ))}
          </div>
          <ol className="mt-4 space-y-3 border-l border-slate-700 pl-4">
            {campaign.events.map((item) => <li key={item.id} className="relative text-sm text-slate-300">
              <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-cyan-300" />
              <span className="text-xs text-slate-500">{item.created_at ? new Date(item.created_at).toLocaleString() : 'Time unavailable'} · {item.event_type}{item.risk_level ? ` · ${item.risk_level} (${item.risk_score})` : ''}</span>
              <p className="mt-1">{item.summary}</p>
              {item.finding_available && item.finding_status && <p className="mt-1 text-xs text-slate-500">Finding #{item.detection_id} · {item.finding_status}</p>}
              {!item.finding_available && <p className="mt-1 text-xs text-slate-500">Historical event; linked finding is no longer available.</p>}
              {Object.keys(item.indicators || {}).length > 0 && <p className="mt-1 break-all text-xs text-slate-500">{JSON.stringify(item.indicators)}</p>}
            </li>)}
          </ol>
        </article>
      ))}
      {campaigns.length === 0 && <p className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 text-sm text-slate-400">No campaign timelines yet. A campaign is tracked only when findings share an exactly matching domain that the URL heuristics classify as suspicious.</p>}
    </div>
  );

  const renderCommunityReports = () => (
    <div className="space-y-4">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">Community report review queue</h3>
        <p className="mt-1 text-sm text-slate-400">Reports and potential matches are local records. Verify evidence before taking action.</p>
      </div>
      {uploadMessage && <p role="status" className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-3 text-sm text-cyan-200">{uploadMessage}</p>}
      {communityReports.map((report) => <article key={report.id} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><span className="text-xs text-slate-500">Report #{report.id} · {report.created_at ? new Date(report.created_at).toLocaleString() : ''}</span><h3 className="mt-1 font-semibold text-white">{brands.find((brand) => brand.id === report.brand_id)?.name || 'Unknown brand'}</h3></div>
          <span className={`rounded-full px-3 py-1 text-xs ${report.status === 'pending' || report.status === 'duplicate' ? 'bg-amber-500/10 text-amber-200' : 'bg-cyan-500/10 text-cyan-200'}`}>{report.status}</span>
        </div>
        <p className="mt-3 whitespace-pre-wrap text-sm text-slate-300">{report.report_text}</p>
        {report.reported_url && <p className="mt-2 break-all text-sm text-cyan-200">{report.reported_url}</p>}
        <div className="mt-4 space-y-2">{report.matches.map((match) => <p key={match.detection_id} className="rounded-lg bg-slate-950/70 p-3 text-xs text-slate-300">Finding #{match.detection_id} · match {Math.round(match.score * 100)}% · {match.reason} {match.analyst_verified ? '· verified' : ''}</p>)}</div>
        <div className="mt-4 flex flex-wrap gap-2">
          <button onClick={() => reviewCommunityReport(report.id, 'reviewed', true)} className="rounded-lg border border-cyan-500/40 px-3 py-2 text-xs text-cyan-200">Verify matches</button>
          <button onClick={() => reviewCommunityReport(report.id, 'actioned', true)} className="rounded-lg border border-amber-500/40 px-3 py-2 text-xs text-amber-200">Mark actioned</button>
          <button onClick={() => reviewCommunityReport(report.id, 'dismissed', false)} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300">Dismiss</button>
        </div>
      </article>)}
      {communityReports.length === 0 && <p className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 text-sm text-slate-400">No customer reports for this organization yet.</p>}
    </div>
  );

  const renderQrScanner = () => (
    <div className="grid gap-5 xl:grid-cols-[1fr,1fr]">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">QR safety analysis</h3>
        <p className="mt-1 text-sm text-slate-400">Upload a QR image to decode it locally. The decoded URL is analyzed as text and is never opened or fetched.</p>
        <form onSubmit={analyzeQrImage} className="mt-4 space-y-3">
          <input required name="image" type="file" accept="image/png,image/jpeg,image/webp" className="w-full rounded-xl border border-slate-700 bg-slate-950 p-3 text-sm text-slate-200" />
          <button disabled={isQrAnalyzing} className="rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950 disabled:cursor-wait disabled:opacity-60">{isQrAnalyzing ? 'Analyzing…' : 'Decode and assess'}</button>
        </form>
        {qrError && <p role="alert" className="mt-4 text-sm text-red-200">{qrError}</p>}
        {qrResult && <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/70 p-4">
          <div className="flex flex-wrap justify-between gap-3"><strong className="text-white">{qrResult.risk_level} risk · {String(qrResult.risk_category).replace('_', ' ')}</strong><span className="text-slate-300">Score {qrResult.risk_score}/100</span></div>
          <p className="mt-2 break-all text-cyan-200">{qrResult.decoded_content || qrResult.decoded_url || 'No content was decoded.'}</p>
          <p className="mt-1 text-xs text-slate-500">Content type: {String(qrResult.content_type || 'URL').replace('_', ' ')} · URL opened: {qrResult.opened ? 'yes' : 'no'}</p>
          <p className="mt-3 text-sm text-slate-300">{qrResult.explanation}</p>
          <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-300">{qrResult.indicators?.map((indicator: { code: string; message: string }) => <li key={indicator.code}>{indicator.message}</li>)}</ul>
          <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-cyan-100">{qrResult.safe_next_steps?.map((step: string) => <li key={step}>{step}</li>)}</ul>
        </div>}
      </section>
      <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">Recent QR checks</h3>
        <div className="mt-4 space-y-3">{qrHistory.map((item) => <div key={item.id} className="rounded-xl bg-slate-950/70 p-3">
          <div className="flex justify-between gap-2 text-sm"><span className="text-white">{item.risk_level} · {item.risk_category?.replace('_', ' ')} · {item.risk_score}</span><span className="text-xs text-slate-500">{item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}</span></div>
          <p className="mt-1 break-all text-xs text-cyan-200">{item.decoded_url}</p>
          {item.explanation && <p className="mt-1 text-xs text-slate-400">{item.explanation}</p>}
        </div>)}
          {qrHistory.length === 0 && <p className="text-sm text-slate-400">No QR checks recorded.</p>}
        </div>
      </section>
    </div>
  );

  const renderTrustCenter = () => (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
      <h3 className="text-lg font-semibold text-white">{trustAssets?.brand_name || currentBrand?.name || 'Brand'} Trust Center</h3>
      <p className="mt-2 text-sm text-amber-200">{trustAssets?.verification_note || 'Official assets are managed by the brand owner and are not independently verified by this demo.'}</p>
      <div className="mt-5 grid gap-3 md:grid-cols-2">{trustAssets?.official_assets?.map((asset: any, index: number) => <div key={`${asset.type}-${asset.value}-${index}`} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="text-xs uppercase tracking-wide text-cyan-200">{asset.type.replace('_', ' ')}</div>
        <div className="mt-2 break-all text-sm text-white">{asset.value}</div>
      </div>)}
        {trustAssets?.official_assets?.length === 0 && <p className="text-sm text-slate-400">No official assets configured. Add them under Brand Profiles.</p>}
      </div>
      <p className="mt-4 text-xs text-slate-500">Local logo fingerprint configured: {trustAssets?.logo_hash_configured ? 'yes' : 'no'}</p>
    </section>
  );

  const renderCustomerPortal = () => (
    <section className="mx-auto max-w-3xl rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
      <h3 className="text-xl font-semibold text-white">Report a suspected scam</h3>
      <p className="mt-2 text-sm text-slate-400">Share a suspicious URL, message, or screenshot for analyst review. Avoid sending passwords or payment details.</p>
      <form onSubmit={submitCustomerReport} className="mt-5 space-y-4">
        <label className="block text-sm text-slate-300">Related brand
          <select name="brand_id" defaultValue={currentBrand?.id || ''} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white">
            <option value="">Not sure</option>{brands.map((brand) => <option key={brand.id} value={brand.id}>{brand.name}</option>)}
          </select>
        </label>
        <label className="block text-sm text-slate-300">Suspicious URL (optional)<input name="reported_url" type="url" placeholder="https://example.invalid" className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" /></label>
        <label className="block text-sm text-slate-300">What happened? (optional when attaching a screenshot)<textarea name="report_text" rows={5} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" /></label>
        <label className="block text-sm text-slate-300">Screenshot (optional)<input name="screenshot" type="file" accept="image/png,image/jpeg,image/webp" className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 p-3 text-sm text-slate-200" /></label>
        <label className="block text-sm text-slate-300">Contact (optional)<input name="reporter_contact" maxLength={255} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" /></label>
        <button disabled={isSubmittingReport} className="rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950 disabled:cursor-wait disabled:opacity-60">{isSubmittingReport ? 'Submitting…' : 'Submit report'}</button>
      </form>
      {uploadMessage && <p role={customerReportResult ? 'status' : 'alert'} className={`mt-4 text-sm ${customerReportResult ? 'text-cyan-200' : 'text-red-200'}`}>{uploadMessage}</p>}
      {customerReportResult && <div className="mt-4 space-y-3 rounded-xl border border-green-500/30 bg-green-950/20 p-4 text-sm text-green-200">
        <p>{customerReportResult.message} Reference #{customerReportResult.report_id}.</p>
        {customerReportResult.ocr_status && <p>OCR status: {customerReportResult.ocr_status}. {customerReportResult.ocr_message}</p>}
        {customerReportResult.extracted_text && <div><h4 className="font-semibold">Text extracted from screenshot</h4><p className="mt-1 whitespace-pre-wrap break-words text-slate-200">{customerReportResult.extracted_text}</p></div>}
        {customerReportResult.analysis && <section className="space-y-2 border-t border-green-500/20 pt-3">
          <h4 className="font-semibold">Local content assessment · {customerReportResult.analysis.risk_category?.replace('_', ' ')} · {customerReportResult.analysis.risk_score}/100</h4>
          <p className="text-slate-200">{customerReportResult.analysis.explanation}</p>
          <ul className="list-inside list-disc text-amber-200">{customerReportResult.analysis.indicators?.map((indicator: { code: string; message: string }, index: number) => <li key={`${indicator.code}-${index}`}>{indicator.message}</li>)}</ul>
          <details className="text-slate-200"><summary className="cursor-pointer">Evidence</summary><ul className="mt-1 list-inside list-disc">{customerReportResult.analysis.evidence?.map((item: { type: string; value: string }, index: number) => <li key={`${item.type}-${index}`}>{item.value}</li>)}</ul></details>
        </section>}
      </div>}
    </section>
  );

  const renderReports = () => (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="text-sm text-slate-400">Total findings</div>
          <div className="mt-2 text-3xl font-bold text-white">{reportData?.summary.total_findings ?? 0}</div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="text-sm text-slate-400">Critical</div>
          <div className="mt-2 text-3xl font-bold text-red-300">{reportData?.summary.critical ?? 0}</div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
          <div className="text-sm text-slate-400">Average risk</div>
          <div className="mt-2 text-3xl font-bold text-cyan-300">{reportData?.summary.risk_score_avg ?? 0}</div>
        </div>
      </div>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-lg font-semibold text-white">Threat export preview</h3>
          <button onClick={exportReport} className="rounded-xl border border-cyan-500/40 px-4 py-2 text-sm text-cyan-200">Download CSV report</button>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-3 pr-4">Entity</th>
                <th className="pb-3 pr-4">Platform</th>
                <th className="pb-3 pr-4">Risk level</th>
                <th className="pb-3 pr-4">Risk score</th>
              </tr>
            </thead>
            <tbody>
              {filteredReportFindings.map((item, index) => (
                <tr key={`${item.entity_name}-${index}`} className="border-t border-slate-800 text-slate-200">
                  <td className="py-3 pr-4">{item.entity_name}</td>
                  <td className="py-3 pr-4">{item.platform}</td>
                  <td className="py-3 pr-4"><span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${statusBadgeClass(item.risk_level)}`}>{item.risk_level}</span></td>
                  <td className="py-3 pr-4">{item.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderSettings = () => (
    <div className="grid gap-6 xl:grid-cols-2">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">AI runtime status</h3>
        <div className="mt-4 space-y-4 text-sm text-slate-300">
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>Local AI engine</span><span className="text-cyan-300">Online</span></div>
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>GPU acceleration</span><span className="text-orange-300">{settings?.gpu_status || 'Unavailable'}</span></div>
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>Detection model</span><span className="text-violet-300">{settings?.ai_runtime || 'NLP + similarity'}</span></div>
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>Optional Ollama</span><span className="text-slate-300">{settings?.ollama_status || 'disabled'}</span></div>
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>QR decoder</span><span className="text-slate-300">{settings?.qr_status || 'unavailable'}</span></div>
          <div className="flex items-center justify-between rounded-xl bg-slate-950/70 p-3"><span>Screenshot OCR</span><span className="text-slate-300">{settings?.ocr_status || 'unavailable'}</span></div>
        </div>
      </div>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
        <h3 className="text-lg font-semibold text-white">Runtime details</h3>
        <div className="mt-4 space-y-4 text-sm text-slate-300">
          <div className="rounded-xl bg-slate-950/70 p-3">Status: {health?.status || 'ok'}</div>
          <div className="rounded-xl bg-slate-950/70 p-3">Demo mode: {health?.demo_mode ? 'enabled' : 'disabled'}</div>
          <div className="rounded-xl bg-slate-950/70 p-3">Runtime: {health?.runtime || 'local'}</div>
        </div>
      </div>
    </div>
  );

  const renderAIChat = () => (
    <section className="mx-auto flex min-h-[min(72vh,760px)] max-w-5xl flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/80 shadow-xl">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 p-5">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-violet-500/40 bg-violet-500/10 text-violet-300"><MessageCircle className="h-5 w-5" /></div>
          <div>
            <h2 className="text-lg font-semibold text-white">AI Chat</h2>
            <p className="text-xs text-slate-400">NVIDIA-hosted Llama · Cybersecurity assistant</p>
          </div>
        </div>
        <button type="button" onClick={clearChat} disabled={isChatSending || chatMessages.length === 0} className="rounded-xl border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-40">Clear chat</button>
      </header>

      <div className="flex-1 space-y-4 overflow-y-auto p-4 sm:p-6" aria-live="polite" aria-label="Chat conversation">
        {chatMessages.length === 0 && (
          <div className="mx-auto mt-10 max-w-lg rounded-2xl border border-slate-800 bg-slate-950/70 p-6 text-center">
            <Sparkles className="mx-auto h-8 w-8 text-violet-300" />
            <h3 className="mt-3 font-medium text-white">How can I help you assess a threat?</h3>
            <p className="mt-2 text-sm text-slate-400">Ask about suspicious messages, domains, phishing indicators, or practical response steps. Chat text is sent to the configured NVIDIA model.</p>
          </div>
        )}
        {chatMessages.map((message) => (
          <div key={message.id} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <article className={`max-w-[92%] whitespace-pre-wrap break-words rounded-2xl px-4 py-3 text-sm leading-relaxed sm:max-w-[80%] ${message.role === 'user' ? 'rounded-br-md border border-cyan-500/30 bg-cyan-500/10 text-cyan-50' : 'rounded-bl-md border border-slate-700 bg-slate-950/80 text-slate-200'}`}>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">{message.role === 'user' ? 'You' : 'BRANDSHIELD AI'}</p>
              {message.content}
            </article>
          </div>
        ))}
        {isChatSending && <div role="status" className="flex justify-start"><div className="rounded-2xl rounded-bl-md border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-300"><span className="inline-flex items-center gap-2"><span className="h-2 w-2 animate-pulse rounded-full bg-violet-400" /><span className="h-2 w-2 animate-pulse rounded-full bg-violet-400 [animation-delay:150ms]" /><span className="h-2 w-2 animate-pulse rounded-full bg-violet-400 [animation-delay:300ms]" />AI is thinking…</span></div></div>}
        <div ref={chatEndRef} />
      </div>

      {chatError && <p role="alert" className="mx-4 mb-3 rounded-xl border border-red-500/30 bg-red-950/30 p-3 text-sm text-red-200 sm:mx-6">{chatError}</p>}

      <form onSubmit={sendChatMessage} className="border-t border-slate-800 p-4 sm:p-5">
        <div className="flex items-end gap-2 sm:gap-3">
          <textarea
            aria-label="Message for AI Chat"
            value={chatInput}
            onChange={(event) => setChatInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
            maxLength={4000}
            rows={2}
            placeholder="Message BRANDSHIELD AI… (Enter to send, Shift+Enter for a new line)"
            className="min-h-[52px] min-w-0 flex-1 resize-y rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
          />
          <button type="submit" aria-label="Send message" disabled={!chatInput.trim() || isChatSending} className="inline-flex h-[52px] shrink-0 items-center gap-2 rounded-xl bg-cyan-500 px-4 font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50">
            <ArrowUpRight className="h-4 w-4" /><span className="hidden sm:inline">{isChatSending ? 'Sending…' : 'Send'}</span>
          </button>
        </div>
        <p className="mt-2 text-right text-xs text-slate-500">{chatInput.length}/4000</p>
      </form>
    </section>
  );

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {sidebarOpen && <button aria-label="Close navigation overlay" onClick={() => setSidebarOpen(false)} className="fixed inset-0 z-30 bg-slate-950/70 lg:hidden" />}
      <aside className={`fixed inset-y-0 left-0 z-40 w-72 border-r border-slate-800 bg-slate-950/95 p-5 backdrop-blur-xl ${sidebarOpen ? '' : 'sidebar-closed'}`}>
        <div className="flex items-center gap-3 border-b border-slate-800 pb-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-violet-500 font-bold text-slate-950">B</div>
          <div>
            <div className="text-xs uppercase tracking-[0.3em] text-cyan-300">Threat intel</div>
            <div className="text-xl font-semibold">BRANDSHIELD AI</div>
          </div>
        </div>

        <nav className="mt-6 space-y-2">
          {navItems.map(({ key, label, icon: Icon }) => (
            <button key={key} onClick={() => { setSelectedTab(key); setSidebarOpen(false); setUploadMessage(''); setActionError(null); }} className={`flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-sm ${selectedTab === key ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-900 hover:text-white'}`}>
              <span className="flex items-center gap-3"><Icon className="h-4 w-4" /> {label}</span>
              <ChevronRight className="h-4 w-4" />
            </button>
          ))}
        </nav>
      </aside>

      <main className="ml-0 min-h-screen p-4 md:p-6 lg:ml-72">
        <header className="flex flex-col gap-4 border-b border-slate-800 pb-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <button aria-label="Open navigation" onClick={() => setSidebarOpen(true)} className="rounded-xl border border-slate-700 p-2 text-slate-200 lg:hidden">
              {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">
              <Search className="h-5 w-5" />
            </div>
            <input aria-label="Search findings by entity, keyword, or risk signal" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search findings by entity, keyword, or risk signal" className="min-w-0 w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-slate-200 lg:w-80" />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div aria-label="Notifications unavailable in this local demo" title="Notifications are not available in this local demo" className="rounded-xl border border-slate-700 p-2 text-slate-500">
              <Bell className="h-5 w-5" />
            </div>
            <label className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200">
              <span className="block text-xs text-slate-400">Current monitored brand</span>
              <select aria-label="Current monitored brand" value={currentBrand?.id || ''} onChange={(event) => setActiveBrandId(Number(event.target.value))} className="max-w-40 bg-transparent font-medium text-white outline-none">
                {brands.map((brand) => <option key={brand.id} value={brand.id} className="bg-slate-900">{brand.name}</option>)}
              </select>
            </label>
            <div className="rounded-xl border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-300">Demo analyst · {health?.runtime || 'local'} session</div>
            <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-300">{settings?.ai_runtime || 'Local AI'} ready</div>
          </div>
        </header>

        <div className="mt-6">
          {actionError && <p role="alert" className="mb-4 rounded-xl border border-red-500/30 bg-red-950/30 p-3 text-sm text-red-200">{actionError}</p>}
          {apiError ? (
            <div role="alert" className="rounded-2xl border border-red-500/30 bg-red-950/30 p-5 text-red-200">
              Platform data could not be loaded: {apiError}
              <button onClick={fetchAll} className="ml-3 underline">Retry</button>
            </div>
          ) : isLoading ? (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-center text-slate-300">Loading platform data…</div>
          ) : selectedTab === 'overview' ? renderOverview() :
            selectedTab === 'ai-chat' ? renderAIChat() :
            selectedTab === 'brands' ? renderBrandProfiles() :
            selectedTab === 'social' ? renderMonitoring('social_profile') :
            selectedTab === 'apps' ? renderMonitoring('application') :
            selectedTab === 'dna' ? renderScamDna() :
            selectedTab === 'investigations' ? renderInvestigations() :
            selectedTab === 'reports' ? renderReports() :
            selectedTab === 'campaigns' ? renderCampaigns() :
            selectedTab === 'community' ? renderCommunityReports() :
            selectedTab === 'qr' ? renderQrScanner() :
            selectedTab === 'trust' ? renderTrustCenter() :
            selectedTab === 'portal' ? renderCustomerPortal() : renderSettings()}
        </div>
      </main>
    </div>
  );
}

export default App;
