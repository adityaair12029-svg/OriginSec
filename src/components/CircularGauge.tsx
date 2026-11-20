import React from 'react';

interface CircularGaugeProps {
  score: number | null;
  label: string;
}

export const CircularGauge: React.FC<CircularGaugeProps> = ({ score, label }) => {
  const size = 108;
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = score !== null ? Math.max(0, Math.min(100, score)) : 0;
  const offset = circumference - (clamped / 100) * circumference;

  const getStrokeColor = (val: number | null) => {
    if (val === null) return '#777267';
    if (val >= 80) return '#00B871';
    if (val >= 50) return '#B86A00';
    return '#DC2626';
  };

  const color = getStrokeColor(score);

  return (
    <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-7 flex flex-col items-center justify-center gap-3.5 transition-colors">
      <div className="relative w-[108px] h-[108px] flex items-center justify-center">
        <svg className="w-[108px] h-[108px] -rotate-90" viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            className="stroke-[#EFECE4] dark:stroke-[#1E1E1E]"
            strokeWidth={strokeWidth}
          />
          {score !== null && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={color}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              style={{ transition: 'stroke-dashoffset 500ms cubic-bezier(0.16, 1, 0.3, 1)' }}
            />
          )}
        </svg>
        <span className="absolute text-[28px] font-bold tabular-nums text-[#151515] dark:text-white">
          {score !== null ? score : 'N/A'}
        </span>
      </div>
      <span className="text-xs font-semibold tracking-[0.18em] uppercase text-[#777267] dark:text-[#929292]">
        {label}
      </span>
    </div>
  );
};
