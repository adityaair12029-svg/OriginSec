import React from 'react';

interface OriginSecMarkProps {
  className?: string;
}

export const OriginSecMark: React.FC<OriginSecMarkProps> = ({ className = 'w-6 h-6' }) => (
  <svg
    viewBox="0 0 32 32"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    className={className}
  >
    <path
      d="M16 3L27.5 26.5C27.85 27.2 27.15 27.95 26.42 27.62L18.4 24.05C16.87 23.37 15.13 23.37 13.6 24.05L5.58 27.62C4.85 27.95 4.15 27.2 4.5 26.5L16 3Z"
      fill="currentColor"
    />
    <path
      d="M16 10.5L20.5 20.2C17.8 19.1 14.2 19.1 11.5 20.2L16 10.5Z"
      fill="#2F71E3"
    />
  </svg>
);
