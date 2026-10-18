import React from 'react';
import { useC1ThemeContext } from '../hooks/useC1Theme.js';

// Theme-Aware SOC Card Container with Hover Magnification
export function SocCard({
  className = '',
  children,
  glow = false,
  hoverable = true,
  isDark: isDarkProp,
}) {
  const ctx = useC1ThemeContext();
  const isDark = isDarkProp !== undefined ? isDarkProp : ctx.isDark;

  return (
    <div
      className={`rounded-2xl p-5 md:p-6 backdrop-blur-xl border transition-all duration-200 ${
        hoverable ? 'c1-hover-card' : ''
      } ${
        isDark
          ? glow
            ? 'bg-[#0b1329]/90 border-cyan-500/40 shadow-[0_4px_30px_rgba(6,182,212,0.14)] text-slate-100'
            : 'bg-[#0b1329]/80 border-slate-800/90 shadow-2xl text-slate-100'
          : glow
          ? 'bg-white border-blue-500/40 shadow-[0_8px_30px_rgba(37,99,235,0.12)] text-slate-900 ring-1 ring-blue-500/20'
          : 'bg-white border-slate-200/90 shadow-[0_4px_24px_-4px_rgba(15,23,42,0.08)] text-slate-900'
      } ${className}`}
    >
      {children}
    </div>
  );
}

// Section Header inside Cards
export function SocSectionHeader({
  icon: Icon,
  iconClass,
  title,
  subtitle,
  badge,
  isDark: isDarkProp,
  children,
}) {
  const ctx = useC1ThemeContext();
  const isDark = isDarkProp !== undefined ? isDarkProp : ctx.isDark;

  const defaultIconClass = isDark
    ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
    : 'text-blue-600 bg-blue-50 border-blue-200';

  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-3 border-b pb-4 ${
        isDark ? 'border-slate-800' : 'border-slate-200'
      }`}
    >
      <div className="flex items-start gap-3">
        {Icon && (
          <span
            className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${
              iconClass || defaultIconClass
            }`}
          >
            <Icon className="h-5 w-5" aria-hidden="true" />
          </span>
        )}
        <div>
          <div className="flex items-center gap-2">
            <h4
              className={`font-manrope text-base font-bold tracking-tight ${
                isDark ? 'text-white' : 'text-slate-900'
              }`}
            >
              {title}
            </h4>
            {badge}
          </div>
          {subtitle && (
            <p className={`text-xs mt-0.5 leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2 text-xs">{children}</div>}
    </div>
  );
}

// Compact Sub-card inside tabs
export function SocSubCard({
  title,
  icon: Icon,
  titleClass,
  badge,
  isDark: isDarkProp,
  className = '',
  children,
}) {
  const ctx = useC1ThemeContext();
  const isDark = isDarkProp !== undefined ? isDarkProp : ctx.isDark;
  const defaultTitleClass = isDark ? 'text-cyan-300' : 'text-blue-700';

  return (
    <div
      className={`space-y-3 rounded-xl p-4 border c1-kpi-card ${
        isDark
          ? 'bg-slate-950/70 border-slate-800/80'
          : 'bg-slate-50 border-slate-200/90 shadow-sm'
      } ${className}`}
    >
      <div
        className={`flex items-center justify-between gap-2 border-b pb-2 ${
          isDark ? 'border-slate-800/60' : 'border-slate-200'
        }`}
      >
        <h5
          className={`flex items-center gap-2 text-xs font-bold uppercase tracking-wider ${
            titleClass || defaultTitleClass
          }`}
        >
          {Icon && <Icon className="h-4 w-4" aria-hidden="true" />}
          <span>{title}</span>
        </h5>
        {badge}
      </div>
      {children}
    </div>
  );
}

// Key-Value row with cybersecurity tones
export function SocRow({
  label,
  value,
  tone = 'default',
  truncate = false,
  tooltip,
  isDark: isDarkProp,
}) {
  const ctx = useC1ThemeContext();
  const isDark = isDarkProp !== undefined ? isDarkProp : ctx.isDark;

  const toneClasses = {
    danger: isDark ? 'text-rose-400 font-bold' : 'text-rose-600 font-bold',
    warn: isDark ? 'text-amber-400 font-semibold' : 'text-amber-600 font-semibold',
    ok: isDark ? 'text-emerald-400 font-medium' : 'text-emerald-700 font-medium',
    cyan: isDark ? 'text-cyan-300 font-medium' : 'text-blue-700 font-medium',
    muted: isDark ? 'text-slate-500' : 'text-slate-400',
    default: isDark ? 'text-slate-200' : 'text-slate-800 font-medium',
  };

  return (
    <div
      className={`flex justify-between gap-3 border-b py-1.5 text-xs last:border-b-0 ${
        isDark ? 'border-slate-800/60' : 'border-slate-200/80'
      }`}
      title={tooltip}
    >
      <span className={isDark ? 'text-slate-400' : 'text-slate-600 font-medium'}>{label}</span>
      <span
        className={`text-right font-mono ${toneClasses[tone] || toneClasses.default} ${
          truncate ? 'max-w-[220px] truncate' : ''
        }`}
        title={truncate ? String(value) : undefined}
      >
        {value !== null && value !== undefined && value !== '' ? (
          String(value)
        ) : (
          <span className={`italic ${isDark ? 'text-slate-600' : 'text-slate-400'}`}>N/A</span>
        )}
      </span>
    </div>
  );
}

// KPI Stat Tile with Hover Magnification
export function SocKpiTile({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'blue',
  subtitle,
  isDark: isDarkProp,
}) {
  const ctx = useC1ThemeContext();
  const isDark = isDarkProp !== undefined ? isDarkProp : ctx.isDark;

  const colorMapDark = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    teal: 'text-teal-400 bg-teal-500/10 border-teal-500/30',
    violet: 'text-violet-400 bg-violet-500/10 border-violet-500/30',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    rose: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };

  const colorMapLight = {
    blue: 'text-blue-700 bg-blue-50 border-blue-200',
    cyan: 'text-cyan-700 bg-cyan-50 border-cyan-200',
    teal: 'text-teal-700 bg-teal-50 border-teal-200',
    violet: 'text-violet-700 bg-violet-50 border-violet-200',
    amber: 'text-amber-800 bg-amber-50 border-amber-200',
    rose: 'text-rose-700 bg-rose-50 border-rose-200',
    emerald: 'text-emerald-700 bg-emerald-50 border-emerald-200',
  };

  const colorClasses = isDark
    ? colorMapDark[tone] || colorMapDark.blue
    : colorMapLight[tone] || colorMapLight.blue;

  return (
    <div
      className={`rounded-xl p-4 border flex items-center justify-between c1-kpi-card ${
        isDark
          ? 'bg-slate-950/80 border-slate-800/80 text-white'
          : 'bg-white border-slate-200/90 shadow-sm text-slate-900'
      }`}
    >
      <div>
        <div
          className={`text-[0.625rem] font-bold uppercase tracking-wider ${
            isDark ? 'text-slate-400' : 'text-slate-500'
          }`}
        >
          {label}
        </div>
        <div className="mt-1 flex items-baseline gap-1 font-mono">
          <span className={`text-xl font-extrabold ${isDark ? 'text-white' : 'text-slate-900'}`}>
            {value}
          </span>
          {unit && <span className={`text-xs ${isDark ? 'text-slate-500' : 'text-slate-500'}`}>{unit}</span>}
        </div>
        {subtitle && (
          <p className={`text-[0.6875rem] mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
            {subtitle}
          </p>
        )}
      </div>
      {Icon && (
        <span
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${colorClasses}`}
        >
          <Icon className="h-5 w-5" />
        </span>
      )}
    </div>
  );
}

