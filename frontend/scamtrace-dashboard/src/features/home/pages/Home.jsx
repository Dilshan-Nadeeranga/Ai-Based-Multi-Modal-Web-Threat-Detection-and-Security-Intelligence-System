import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  ArrowDown,
  ArrowRight,
  Bitcoin,
  BookOpen,
  Brain,
  Bug,
  Building2,
  CircleAlert,
  CircleCheck,
  Code,
  Eye,
  FileCode,
  FileText,
  Fingerprint,
  GitBranch,
  Globe,
  GraduationCap,
  Image,
  Languages,
  Layers,
  Link as LinkIcon,
  LockOpen,
  MessageSquare,
  Network,
  Radar,
  ScanSearch,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShoppingCart,
  Sparkles,
  TriangleAlert,
  Upload,
  UserCheck,
  Workflow,
} from 'lucide-react'
import HomeFooter from '../components/HomeFooter.jsx'
import HomeHeader from '../components/HomeHeader.jsx'

const SECTION = 'w-full scroll-mt-20 py-10 lg:py-16'
const CONTAINER = 'mx-auto flex w-full max-w-7xl flex-col gap-10 px-4 lg:px-12'
const EYEBROW = 'text-[0.6875rem] font-bold uppercase tracking-wider text-st-blue-dark'
const H2 = 'font-manrope text-[1.75rem] font-bold leading-tight tracking-tight text-st-navy lg:text-4xl'
const CARD = 'rounded-2xl bg-white shadow-sm transition-all hover:shadow-md'
const ICON_TILE = 'flex items-center justify-center rounded-xl bg-st-container p-3 text-st-blue-dark'

const EXAMPLE_SIGNALS = [
  {
    icon: LinkIcon,
    title: 'URL & Domain Intelligence',
    score: 78,
    detail: 'Recently registered domain, look-alike brand keywords and an unusual top-level domain.',
  },
  {
    icon: Code,
    title: 'HTML Content & Behavior',
    score: 84,
    detail: 'Password form posting to an external domain, urgent wording and obfuscated JavaScript.',
  },
  {
    icon: Image,
    title: 'Social & Visual Analysis',
    score: 90,
    detail: 'Screenshot text and logo resemble a known bank, but the destination domain does not match.',
  },
]

const THREAT_TYPES = [
  {
    icon: Fingerprint,
    title: 'Phishing & Credential Theft',
    text: 'Fake sign-in pages and forms that collect passwords, OTPs or card details.',
  },
  {
    icon: ShoppingCart,
    title: 'Fake E-Commerce',
    text: 'Online stores that take payment for products that are never delivered.',
  },
  {
    icon: Bitcoin,
    title: 'Crypto & Investment Scams',
    text: 'Fake airdrops, giveaways and "guaranteed return" investment schemes.',
  },
  {
    icon: ShieldAlert,
    title: 'Brand Impersonation',
    text: 'Websites and social media posts that copy the look of trusted brands.',
  },
]

const EXAMPLE_INDICATORS = [
  {
    indicator: 'Look-alike domain registered a few days ago',
    source: 'URL',
    sourceIcon: Globe,
    threat: 'Phishing',
    component: 'C1',
  },
  {
    indicator: 'Hidden password form that posts to an external domain',
    source: 'Web page HTML',
    sourceIcon: Code,
    threat: 'Credential harvesting',
    component: 'C2',
  },
  {
    indicator: 'Obfuscated script that decodes and runs a payload',
    source: 'JavaScript',
    sourceIcon: FileCode,
    threat: 'Malware delivery',
    component: 'C2',
  },
  {
    indicator: "Post screenshot reusing a bank's logo and urgent text",
    source: 'Social media post',
    sourceIcon: MessageSquare,
    threat: 'Brand impersonation',
    component: 'C3',
  },
  {
    indicator: 'Hard-coded API key committed to a public repository',
    source: 'Source code',
    sourceIcon: GitBranch,
    threat: 'Secret exposure',
    component: 'C4',
  },
]

const PIPELINE_STEPS = [
  {
    icon: Upload,
    title: 'Submit',
    text: 'Provide a suspicious URL, social media post or screenshot, or a public GitHub repository through the dashboard.',
  },
  {
    icon: ScanSearch,
    title: 'Analyze',
    text: 'Each specialised component examines its own evidence: URL and domain, page content and scripts, images and text, or source code.',
  },
  {
    icon: Network,
    title: 'Correlate',
    text: 'The API Gateway combines the component results into one overall risk score and threat label.',
  },
  {
    icon: FileText,
    title: 'Explain',
    text: 'Results include the evidence behind the score, so users can understand why something was flagged.',
  },
]

const MODULES = [
  {
    code: 'C1',
    icon: Globe,
    title: 'Intelligent URL & Domain Analyzer',
    text: 'Analyzes the structure of a URL and the reputation signals of its domain using machine learning models trained on public phishing and malware URL feeds.',
    tags: ['Lexical URL Features', 'Domain Signals', 'ML Classification'],
    to: '/url-analyzer',
  },
  {
    code: 'C2',
    icon: Code,
    title: 'HTML Content & Behavior Analyzer',
    text: 'Inspects the DOM structure of a page, classifies multilingual text (English, Sinhala and Tamil) for social-engineering intent, and statically analyzes JavaScript without executing it.',
    tags: ['DOM Structure', 'Multilingual NLP', 'Static JavaScript Analysis'],
    to: '/c2',
  },
  {
    code: 'C3',
    icon: Eye,
    title: 'Social Media & Web Visual Threat Analyzer',
    text: 'Extracts text from social media screenshots with OCR, captures the destination web page, and compares visual evidence against known brands to detect impersonation.',
    tags: ['OCR', 'Web Page Capture', 'Brand Comparison'],
    to: '/social-visual-analysis',
  },
  {
    code: 'C4',
    icon: Bug,
    title: 'Code Quality & Vulnerability Auditor',
    text: 'Audits public GitHub repositories with AST-based static analysis to find vulnerabilities, exposed secrets and code quality issues, then suggests fixes for human review.',
    tags: ['AST Static Analysis', 'Secret Detection', 'Reviewed Remediation'],
    to: '/code-audit',
  },
]

const INPUTS = [
  { icon: MessageSquare, label: 'Social Media Post' },
  { icon: LinkIcon, label: 'Suspicious URL' },
  { icon: Image, label: 'Screenshot' },
  { icon: GitBranch, label: 'GitHub Repository' },
]

const EVIDENCE = [
  'Logo resembles a known bank',
  'Domain registered 2 days ago',
  'Urgent, threatening language',
  'Form posts to an external domain',
]

const ADVANTAGES = [
  {
    icon: Sparkles,
    title: 'Explainable Results',
    text: 'Every score comes with the findings that produced it, instead of an unexplained "safe" or "unsafe" label.',
  },
  {
    icon: Layers,
    title: 'Multi-Modal Detection',
    text: 'URL, page content, scripts, images and code are analyzed together, so a threat missed by one signal can be caught by another.',
  },
  {
    icon: Shield,
    title: 'Safe Analysis',
    text: 'JavaScript and repository code are analyzed statically. Untrusted code is never executed on the platform.',
  },
  {
    icon: UserCheck,
    title: 'Human in the Loop',
    text: 'AI-suggested code fixes are reviewed and approved by a person before they are accepted.',
  },
]

const RESEARCH_PILLARS = [
  { icon: Brain, title: 'Multi-Modal Threat Analysis', text: 'Independent models for each type of evidence.' },
  { icon: Sparkles, title: 'Explainable Intelligence', text: 'Clear evidence for every decision.' },
  { icon: Workflow, title: 'Cross-Modal Correlation', text: 'Component results combined into one risk view.' },
  { icon: Languages, title: 'Local Language Support', text: 'Scam content analysis in English, Sinhala and Tamil.' },
]

const RESEARCH_FACTS = [
  { value: '4', label: 'Analysis Components' },
  { value: '3', label: 'Content Languages' },
  { value: '1', label: 'Unified Risk Report' },
]

function Eyebrow({ icon: Icon, children }) {
  return (
    <span className="inline-flex items-center gap-1.5 self-start rounded-full bg-st-low px-4 py-1.5 shadow-sm">
      {Icon && <Icon className="h-4 w-4 text-st-blue-dark" aria-hidden="true" />}
      <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-navy">{children}</span>
    </span>
  )
}

function SectionHeading({ eyebrow, title, text, center = false }) {
  return (
    <div className={`flex max-w-3xl flex-col gap-2 ${center ? 'mx-auto items-center text-center' : ''}`}>
      <span className={EYEBROW}>{eyebrow}</span>
      <h2 className={H2}>{title}</h2>
      {text && <p className="text-base text-st-muted">{text}</p>}
    </div>
  )
}

function ScoreRing({ score }) {
  return (
    <div className="relative flex h-16 w-16 items-center justify-center">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 36 36" aria-hidden="true">
        <path
          className="text-st-highest"
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
        />
        <path
          className="text-st-error"
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none"
          stroke="currentColor"
          strokeDasharray={`${score}, 100`}
          strokeLinecap="round"
          strokeWidth="3.5"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-manrope text-xl font-extrabold leading-none text-st-error">{score}</span>
        <span className="text-[0.6875rem] text-st-muted">/ 100</span>
      </div>
    </div>
  )
}

function HeroSection() {
  return (
    <section id="top" className="st-blue-backdrop relative w-full scroll-mt-20 overflow-hidden py-10 lg:py-16">
      <div className="pointer-events-none absolute -top-32 right-1/4 h-96 w-96 rounded-full bg-st-blue/10 blur-3xl" />
      <div className="relative mx-auto grid w-full max-w-7xl grid-cols-1 items-center gap-8 px-4 lg:grid-cols-12 lg:px-12">
        <div className="flex flex-col gap-6 lg:col-span-6">
          <span className="inline-flex items-center gap-2 self-start rounded-full bg-st-low px-4 py-1.5 shadow-sm">
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-st-blue opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-st-blue" />
            </span>
            <span className="text-xs font-bold uppercase tracking-wider text-st-navy">AI-Powered Web Threat Intelligence</span>
          </span>

          <div className="flex flex-col gap-3">
            <h1 className="font-manrope text-4xl font-extrabold leading-tight tracking-tight text-st-navy lg:text-[3.5rem] lg:leading-[4.25rem]">
              Detect <span className="text-st-blue">Web Threats</span> Before They Become Attacks.
            </h1>
            <p className="max-w-xl text-lg leading-relaxed text-st-muted">
              ScamTrace combines URL intelligence, web page behavior, social media evidence and visual analysis to
              identify phishing, scams, brand impersonation and malicious web infrastructure.
            </p>
          </div>

          <div className="flex flex-col items-stretch gap-4 pt-1 sm:flex-row sm:items-center">
            <Link
              to="/url-analyzer"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-st-blue px-7 py-3.5 text-sm font-semibold text-white shadow-lg shadow-st-blue/25 transition-all hover:bg-st-navy-2 hover:shadow-xl"
            >
              <ShieldAlert className="h-5 w-5" aria-hidden="true" />
              Analyze a Threat
            </Link>
            <Link
              to="/code-audit"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-white px-6 py-3.5 text-sm font-semibold text-st-navy shadow-sm ring-1 ring-st-container transition-all hover:bg-st-low hover:shadow"
            >
              <GitBranch className="h-5 w-5 text-st-blue-dark" aria-hidden="true" />
              Audit a Repository
            </Link>
          </div>

          <div className="flex flex-col gap-4 pt-2">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs font-bold text-st-muted">
              <span><span className="text-st-blue-dark">●</span> Multi-Modal Analysis</span>
              <span className="text-st-outline">•</span>
              <span><span className="text-st-blue-dark">●</span> Explainable Results</span>
              <span className="text-st-outline">•</span>
              <span><span className="text-st-blue-dark">●</span> Research-Driven</span>
            </div>
            <div className="grid grid-cols-3 gap-4">
              {[
                { value: '4', label: 'Analysis Components' },
                { value: '5+', label: 'Threat Categories' },
                { value: '3', label: 'Content Languages' },
              ].map((stat) => (
                <div key={stat.label} className="flex flex-col rounded-lg bg-st-low p-3 shadow-sm">
                  <span className="font-manrope text-xl font-extrabold text-st-navy">{stat.value}</span>
                  <span className="text-[0.6875rem] font-bold text-st-muted">{stat.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-center lg:col-span-6 lg:justify-end">
          <div className="relative flex w-full max-w-xl flex-col gap-4 rounded-2xl bg-white p-4 shadow-xl ring-1 ring-st-container">
            <span className="absolute -right-3 -top-3 flex items-center gap-1 rounded-full bg-st-navy px-3 py-1 text-[0.6875rem] font-bold text-white shadow-md">
              <TriangleAlert className="h-3.5 w-3.5" aria-hidden="true" /> Example Report
            </span>

            <div className="flex items-center justify-between gap-2 rounded-xl bg-st-low p-1.5">
              <div className="flex items-center gap-1.5 px-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-st-error" />
                <span className="h-2.5 w-2.5 rounded-full bg-st-fixed-dim" />
                <span className="h-2.5 w-2.5 rounded-full bg-st-highest" />
              </div>
              <div className="flex min-w-0 flex-1 items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 shadow-sm">
                <LockOpen className="h-4 w-4 shrink-0 text-st-error" aria-hidden="true" />
                <span className="truncate font-mono text-xs text-st-ink">https://secure-login-bank-update.example/auth</span>
              </div>
              <span className="whitespace-nowrap rounded-full bg-st-error-bg px-2.5 py-1 text-[0.6875rem] font-bold text-st-error-ink">
                MALICIOUS
              </span>
            </div>

            <div className="flex items-center justify-between gap-4 rounded-xl bg-st-low p-4 shadow-sm">
              <div className="flex items-center gap-4">
                <ScoreRing score={87} />
                <div className="flex flex-col">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-manrope text-xl font-bold text-st-navy">Threat Score</span>
                    <span className="rounded-full bg-st-error px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-wide text-white">High Risk</span>
                  </div>
                  <span className="text-sm text-st-muted">Category: Brand Impersonation (Banking)</span>
                </div>
              </div>
              <ShieldCheck className="hidden h-8 w-8 text-st-blue sm:block" aria-hidden="true" />
            </div>

            <div className="flex flex-col gap-2">
              <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-muted">Signals by Component</span>
              {EXAMPLE_SIGNALS.map(({ icon: Icon, title, score, detail }) => (
                <div key={title} className={`${CARD} flex items-start justify-between gap-2 p-3 ring-1 ring-st-low`}>
                  <div className="flex items-start gap-3">
                    <span className="flex items-center justify-center rounded-lg bg-st-container p-2 text-st-blue-dark">
                      <Icon className="h-5 w-5" aria-hidden="true" />
                    </span>
                    <div className="flex flex-col">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-bold text-st-ink">{title}</span>
                        <span className="text-[0.6875rem] font-semibold text-st-error">{score} / 100</span>
                      </div>
                      <span className="text-sm text-st-muted">{detail}</span>
                    </div>
                  </div>
                  <CircleAlert className="h-5 w-5 shrink-0 text-st-error" aria-hidden="true" />
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between pt-1 text-[0.6875rem] text-st-muted">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 animate-pulse rounded-full bg-st-blue" />
                Illustrative example – not a real scan
              </span>
              <Link to="/url-analyzer" className="inline-flex items-center gap-0.5 font-bold text-st-blue hover:underline">
                Try it yourself <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

function ThreatsSection() {
  return (
    <section id="threats" className={`${SECTION} bg-st-low`}>
      <div className={CONTAINER}>
        <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div className="flex max-w-2xl flex-col gap-2">
            <Eyebrow icon={Radar}>Threat Coverage</Eyebrow>
            <h2 className={H2}>Threats ScamTrace Is Built to Detect</h2>
            <p className="text-base text-st-muted">
              Modern scams spread across links, web pages, social media and code. ScamTrace looks at each of these
              channels to find the warning signs.
            </p>
          </div>
          <Link
            to="/url-analyzer"
            className="inline-flex shrink-0 items-center gap-2 self-start whitespace-nowrap rounded-xl bg-st-navy px-6 py-2.5 text-sm font-semibold text-white shadow-md transition-all hover:bg-st-navy-2 md:self-auto"
          >
            <Radar className="h-5 w-5" aria-hidden="true" />
            Start an Analysis
          </Link>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {THREAT_TYPES.map(({ icon: Icon, title, text }) => (
            <div key={title} className={`${CARD} flex flex-col gap-3 p-5`}>
              <span className={`${ICON_TILE} self-start bg-st-low p-2.5`}>
                <Icon className="h-5 w-5" aria-hidden="true" />
              </span>
              <h3 className="font-manrope text-lg font-bold text-st-navy">{title}</h3>
              <p className="text-sm text-st-muted">{text}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-col overflow-hidden rounded-2xl bg-white shadow-md">
          <div className="flex items-center justify-between gap-2 bg-st-container p-4">
            <div className="flex items-center gap-2">
              <ScanSearch className="h-5 w-5 text-st-navy" aria-hidden="true" />
              <span className="text-sm font-bold text-st-navy">Example Indicators and the Component That Detects Them</span>
            </div>
            <span className="hidden text-[0.6875rem] text-st-muted sm:inline">Illustrative examples</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-st-low text-[0.6875rem] uppercase text-st-muted">
                <tr>
                  <th className="px-4 py-3 font-bold">Indicator</th>
                  <th className="px-4 py-3 font-bold">Source</th>
                  <th className="px-4 py-3 font-bold">Threat Type</th>
                  <th className="px-4 py-3 font-bold">Component</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-st-low">
                {EXAMPLE_INDICATORS.map(({ indicator, source, sourceIcon: SourceIcon, threat, component }) => (
                  <tr key={indicator} className="transition-colors hover:bg-st-low/50">
                    <td className="px-4 py-3 font-semibold text-st-ink">{indicator}</td>
                    <td className="px-4 py-3 text-st-muted">
                      <span className="flex items-center gap-1.5 whitespace-nowrap">
                        <SourceIcon className="h-4 w-4 text-st-blue-dark" aria-hidden="true" /> {source}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-st-ink">{threat}</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex rounded-full bg-st-highest px-2.5 py-0.5 text-[0.6875rem] font-bold text-st-navy">
                        {component}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  )
}

function HowItWorksSection() {
  return (
    <section id="how-it-works" className={`${SECTION} bg-white`}>
      <div className={CONTAINER}>
        <SectionHeading
          center
          eyebrow="Analysis Pipeline"
          title="One Platform. Multiple Layers of Intelligence."
          text="From a suspicious input to an explainable risk assessment in four steps."
        />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          {PIPELINE_STEPS.map(({ icon: Icon, title, text }, index) => (
            <div key={title} className="flex flex-col gap-3 rounded-2xl bg-st-low p-6 shadow-sm transition-all hover:shadow-md">
              <div className="flex items-center justify-between">
                <span className={ICON_TILE}>
                  <Icon className="h-6 w-6" aria-hidden="true" />
                </span>
                <span className="font-manrope text-2xl font-black text-st-blue-dark/30">
                  {String(index + 1).padStart(2, '0')}
                </span>
              </div>
              <h3 className="font-manrope text-xl font-bold text-st-navy">{title}</h3>
              <p className="text-sm leading-relaxed text-st-muted">{text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function ModulesSection() {
  return (
    <section id="modules" className={`${SECTION} bg-st-low`}>
      <div className={CONTAINER}>
        <SectionHeading
          eyebrow="Analysis Components"
          title="Core Threat Detection Capabilities"
          text="Four research components, each focused on a different type of evidence."
        />
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          {MODULES.map(({ code, icon: Icon, title, text, tags, to }) => (
            <div key={code} className={`${CARD} flex flex-col justify-between gap-4 p-6`}>
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className={ICON_TILE}>
                    <Icon className="h-6 w-6" aria-hidden="true" />
                  </span>
                  <span className="rounded-full bg-st-low px-2.5 py-1 text-[0.6875rem] font-bold text-st-blue">
                    Component {code}
                  </span>
                </div>
                <h3 className="font-manrope text-2xl font-bold text-st-navy">{title}</h3>
                <p className="text-base text-st-muted">{text}</p>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap gap-2">
                  {tags.map((tag) => (
                    <span key={tag} className="rounded-full bg-st-container px-3 py-1 text-[0.6875rem] font-bold text-st-navy">
                      {tag}
                    </span>
                  ))}
                </div>
                {to && (
                  <Link to={to} className="inline-flex items-center gap-1 text-sm font-bold text-st-blue hover:underline">
                    Open <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function FlowArrow() {
  return (
    <div className="flex items-center justify-center py-1">
      <span className="rounded-full bg-st-blue-dark p-2 text-white">
        <ArrowDown className="h-4 w-4" aria-hidden="true" />
      </span>
    </div>
  )
}

function ArchitectureSection() {
  return (
    <section id="architecture" className={`${SECTION} bg-white`}>
      <div className={CONTAINER}>
        <SectionHeading
          center
          eyebrow="System Architecture"
          title="Multi-Modal Threat Correlation"
          text="Combining evidence from several sources reduces false alarms and catches threats that a single check would miss."
        />
        <div className="grid grid-cols-1 items-center gap-8 lg:grid-cols-12">
          <div className="flex flex-col gap-4 rounded-2xl bg-st-low p-6 shadow-sm lg:col-span-6">
            <span className="text-[0.6875rem] font-bold uppercase text-st-navy">Inputs</span>
            <div className="grid grid-cols-2 gap-2">
              {INPUTS.map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-2 rounded-xl bg-white p-3 shadow-sm">
                  <Icon className="h-5 w-5 text-st-blue-dark" aria-hidden="true" />
                  <span className="text-xs font-semibold text-st-ink">{label}</span>
                </div>
              ))}
            </div>
            <FlowArrow />
            <div className="flex items-center gap-4 rounded-xl bg-st-navy p-4 text-white shadow-md">
              <Server className="h-9 w-9 shrink-0 text-st-fixed" aria-hidden="true" />
              <div className="flex flex-col">
                <span className="font-manrope text-lg font-bold">API Gateway & Analysis Components (C1–C4)</span>
                <span className="text-sm text-st-fixed-dim">
                  Authenticated requests are routed to the matching components and their results are combined.
                </span>
              </div>
            </div>
            <FlowArrow />
            <div className="flex items-center justify-between gap-2 rounded-xl bg-white p-3 shadow-sm">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-st-blue" aria-hidden="true" />
                <span className="text-sm font-bold text-st-navy">Explainable Threat Report</span>
              </div>
              <span className="font-mono text-[0.6875rem] font-bold text-st-blue-dark">Score • Label • Evidence</span>
            </div>
          </div>

          <div className="flex flex-col gap-4 rounded-2xl bg-white p-6 shadow-xl ring-1 ring-st-container lg:col-span-6">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-6 w-6 text-st-error" aria-hidden="true" />
                <span className="font-manrope text-xl font-bold text-st-navy">Example Analysis Report</span>
              </div>
              <span className="rounded-full bg-st-error-bg px-3 py-1 text-[0.6875rem] font-extrabold text-st-error-ink">
                HIGH RISK
              </span>
            </div>
            <div className="grid grid-cols-2 gap-4 rounded-xl bg-st-low p-4">
              <div className="flex flex-col">
                <span className="text-[0.6875rem] uppercase text-st-muted">Threat Classification</span>
                <span className="font-manrope text-lg font-bold text-st-ink">Brand Impersonation</span>
                <span className="text-sm text-st-blue-dark">Banking phishing</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[0.6875rem] uppercase text-st-muted">Overall Risk Score</span>
                <span className="font-manrope text-lg font-bold text-st-navy">87 / 100</span>
                <span className="text-sm text-st-muted">3 of 3 components flagged</span>
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <span className="text-[0.6875rem] font-bold uppercase text-st-muted">Evidence</span>
              <div className="flex flex-wrap gap-2">
                {EVIDENCE.map((item) => (
                  <span key={item} className="flex items-center gap-1.5 rounded-lg bg-st-container px-3 py-1.5 text-xs font-medium text-st-navy">
                    <CircleCheck className="h-4 w-4 text-st-error" aria-hidden="true" />
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-1 rounded-xl bg-st-high p-3 font-mono text-sm text-st-ink">
              <span className="text-[0.6875rem] font-bold text-st-blue-dark">// RECOMMENDATION</span>
              <span>Do not enter credentials. Report the link to the impersonated organization.</span>
            </div>
            <span className="text-[0.6875rem] text-st-muted">Illustrative example – not a real scan.</span>
          </div>
        </div>
      </div>
    </section>
  )
}

function AdvantagesSection() {
  return (
    <section className={`${SECTION} bg-st-low`}>
      <div className={CONTAINER}>
        <SectionHeading
          center
          eyebrow="Why ScamTrace"
          title="Beyond Simple Blocklists"
          text="Blocklists only know about threats that have already been reported. ScamTrace analyzes the evidence itself."
        />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          {ADVANTAGES.map(({ icon: Icon, title, text }) => (
            <div key={title} className={`${CARD} flex flex-col gap-3 p-6`}>
              <span className={`${ICON_TILE} self-start`}>
                <Icon className="h-6 w-6" aria-hidden="true" />
              </span>
              <h3 className="font-manrope text-xl font-bold text-st-navy">{title}</h3>
              <p className="text-sm text-st-muted">{text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function ResearchSection() {
  return (
    <section id="research" className={`${SECTION} bg-white`}>
      <div className="mx-auto grid w-full max-w-7xl grid-cols-1 items-center gap-8 px-4 lg:grid-cols-12 lg:px-12">
        <div className="flex flex-col gap-6 lg:col-span-7">
          <Eyebrow icon={GraduationCap}>Academic Research</Eyebrow>
          <div className="flex flex-col gap-3">
            <h2 className={H2}>Built as a Cybersecurity Research Project</h2>
            <p className="text-lg text-st-muted">
              ScamTrace is a final year research project that studies how combining several types of evidence
              improves the detection of web threats compared with single-signal approaches.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {RESEARCH_PILLARS.map(({ icon: Icon, title, text }) => (
              <div key={title} className="flex items-start gap-3">
                <Icon className="mt-0.5 h-5 w-5 shrink-0 text-st-blue-dark" aria-hidden="true" />
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-st-navy">{title}</span>
                  <span className="text-sm text-st-muted">{text}</span>
                </div>
              </div>
            ))}
          </div>
          <div>
            <a
              href="#modules"
              className="inline-flex items-center gap-2 rounded-xl bg-st-navy px-6 py-2.5 text-sm font-semibold text-white shadow-md transition-all hover:bg-st-navy-2"
            >
              <BookOpen className="h-5 w-5" aria-hidden="true" />
              Explore the Components
            </a>
          </div>
        </div>

        <div className="flex flex-col gap-4 lg:col-span-5">
          <div className="grid grid-cols-3 gap-2">
            {RESEARCH_FACTS.map((fact) => (
              <div key={fact.label} className="flex flex-col items-center justify-center rounded-xl bg-st-low p-4 text-center shadow-sm">
                <span className="font-manrope text-2xl font-extrabold text-st-navy">{fact.value}</span>
                <span className="text-[0.6875rem] font-bold text-st-muted">{fact.label}</span>
              </div>
            ))}
          </div>
          <div className="flex flex-col gap-3 rounded-2xl bg-st-low p-6 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-blue-dark">Affiliation</span>
              <Building2 className="h-5 w-5 text-st-blue-dark" aria-hidden="true" />
            </div>
            <div className="flex flex-col gap-1">
              <span className="font-manrope text-xl font-bold text-st-navy">Sri Lanka Institute of Information Technology</span>
              <span className="text-sm text-st-muted">Faculty of Computing – Final Year Research Project</span>
              <span className="mt-1 font-mono text-xs font-semibold text-st-blue">Project ID: J26-SE-316</span>
            </div>
            <p className="border-t border-st-container pt-2 text-sm leading-relaxed text-st-muted">
              “ScamTrace: AI-Based Multi-Modal Web Threat Detection and Security Intelligence System.”
            </p>
          </div>
        </div>
      </div>
    </section>
  )
}

function CallToActionSection() {
  return (
    <section className={`${SECTION} bg-white pt-0 lg:pt-0`}>
      <div className="mx-auto w-full max-w-7xl px-4 lg:px-12">
        <div className="relative flex flex-col items-center justify-between gap-6 overflow-hidden rounded-3xl bg-gradient-to-r from-st-navy to-st-navy-2 p-8 shadow-2xl md:flex-row lg:p-10">
          <div className="pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full bg-st-blue/20 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-24 -left-24 h-80 w-80 rounded-full bg-st-blue-dark/30 blur-3xl" />
          <div className="z-10 flex max-w-xl flex-col gap-3">
            <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-fixed">Check Before You Click</span>
            <h2 className="font-manrope text-[1.75rem] font-bold leading-tight text-white lg:text-4xl">Not Sure If a Link Is Safe?</h2>
            <p className="text-lg leading-relaxed text-st-fixed-dim">
              Submit a suspicious link or post and ScamTrace will analyze the available evidence and explain the
              risk it finds.
            </p>
          </div>
          <div className="z-10 flex w-full flex-col items-center gap-4 sm:flex-row md:w-auto">
            <Link
              to="/url-analyzer"
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-st-blue px-8 py-4 text-sm font-semibold text-white shadow-lg transition-all hover:bg-st-blue-dark sm:w-auto"
            >
              <Shield className="h-5 w-5" aria-hidden="true" />
              Start Analysis
            </Link>
            <Link
              to="/social-visual-analysis"
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-white/10 px-7 py-4 text-sm font-semibold text-white transition-all hover:bg-white/20 sm:w-auto"
            >
              <MessageSquare className="h-5 w-5" aria-hidden="true" />
              Analyze a Post
            </Link>
          </div>
        </div>
      </div>
    </section>
  )
}

export default function Home() {
  const { hash, key } = useLocation()

  // Router navigation does not scroll to "#section" by itself (e.g. links from /login).
  useEffect(() => {
    if (!hash) return
    document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ behavior: 'smooth' })
  }, [hash, key])

  return (
    <div className="flex min-h-screen w-full flex-col bg-white font-inter text-st-ink antialiased">
      <HomeHeader />
      <main className="w-full flex-1 pt-20">
        <HeroSection />
        <ThreatsSection />
        <HowItWorksSection />
        <ModulesSection />
        <ArchitectureSection />
        <AdvantagesSection />
        <ResearchSection />
        <CallToActionSection />
      </main>
      <HomeFooter />
    </div>
  )
}
