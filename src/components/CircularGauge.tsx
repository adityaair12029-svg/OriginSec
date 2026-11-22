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
    if (val === null) return '#5A606E';
    if (val >= 80) return '#2F71E3';
    if (val >= 50) return '#D97706';
    return '#DC2626';
  };

  const color = getStrokeColor(score);

  return (
    <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-7 flex flex-col items-center justify-center gap-3.5 transition-colors">
      <div className="relative w-[108px] h-[108px] flex items-center justify-center">
        <svg className="w-[108px] h-[108px] -rotate-90" viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            className="stroke-[#E5E7EB] dark:stroke-white/[0.08]"
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
        <span className="absolute text-[28px] font-bold tabular-nums text-[#0A0A0C] dark:text-white">
          {score !== null ? score : 'N/A'}
        </span>
      </div>
      <span className="text-xs font-semibold tracking-[0.18em] uppercase text-[#5A606E] dark:text-[#9499A6]">
        {label}
      </span>
    </div>
  );
};
