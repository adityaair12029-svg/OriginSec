import React, { useEffect, useRef } from 'react';
import type { ThemeMode } from '../types/audit';

interface ParticleFieldCanvasProps {
  theme: ThemeMode;
  variant?: 'hero' | 'wave';
  className?: string;
}

interface Particle {
  baseX: number;
  baseY: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  length: number;
  phase: number;
  hueIndex: number;
  alpha: number;
  isDot: boolean;
}

// Restrained Antigravity palette matching subtle orbital micro-dashes & calm dots
const LIGHT_HERO_COLORS = ['#2F75C3', '#4F6BED', '#6366F1', '#D97757', '#7E8798'];
const DARK_HERO_COLORS = ['#3B82F6', '#60A5FA', '#818CF8', '#94A3B8', '#E2E8F0'];

export const ParticleFieldCanvas: React.FC<ParticleFieldCanvasProps> = ({
  theme,
  variant = 'hero',
  className = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const pointerRef = useRef<{ x: number; y: number; active: boolean }>({ x: 0, y: 0, active: false });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = 0;
    let height = 0;
    let dpr = 1;
    let particles: Particle[] = [];
    let rafId: number | null = null;
    let timerId: number | null = null;
    let disposed = false;
    let tick = 0;

    const initParticles = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);

      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      particles = [];

      if (variant === 'wave') {
        // Dense yet calm undulating dot horizon framing the Login card
        const cols = width < 640 ? 24 : 38;
        const rows = width < 640 ? 10 : 14;
        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols; c++) {
            const nx = (c + 0.5) / cols;
            const ny = 0.52 + (r / rows) * 0.46;
            const waveOffset = Math.sin(nx * Math.PI * 3.2 + r * 0.42) * 16;
            const bx = nx * width;
            const by = ny * height + waveOffset;
            particles.push({
              baseX: bx,
              baseY: by,
              x: bx,
              y: by,
              vx: 0,
              vy: 0,
              size: 1.2 + ((r + c) % 3) * 0.45,
              length: 2,
              phase: nx * 6.28 + r * 0.45,
              hueIndex: (r * 3 + c) % 5,
              alpha: 0.18 + (r / rows) * 0.36,
              isDot: true,
            });
          }
        }
      } else {
        // Dense, soft Antigravity orbital halo keeping center text crisp & readable
        const count = width < 640 ? 210 : 380;
        const cx = width * 0.48;
        const cy = height * 0.44;
        const minRadius = Math.min(width, height) * 0.16;
        const maxRadius = Math.max(width, height) * 0.68;

        for (let i = 0; i < count; i++) {
          const frac = (i + 1) / count;
          const angle = i * 2.3999632; // Golden-angle phyllotaxis spacing
          const radius = minRadius + Math.pow(frac, 0.72) * (maxRadius - minRadius);
          const bx = cx + Math.cos(angle) * radius;
          const by = cy + Math.sin(angle) * radius * 0.78;
          // Quiet central halo fade so headline contrast stays pristine
          const distFromCenter = Math.hypot((bx - cx) / (width * 0.35), (by - cy) / (height * 0.35));
          const centerFade = Math.min(1, Math.max(0.28, distFromCenter * 0.85));

          particles.push({
            baseX: bx,
            baseY: by,
            x: bx,
            y: by,
            vx: 0,
            vy: 0,
            size: 1.35 + (i % 3) * 0.35,
            length: 2.6 + (i % 4) * 1.1,
            phase: angle,
            hueIndex: i % 5,
            alpha: (0.2 + (i % 4) * 0.085) * centerFade,
            isDot: i % 3 === 0,
          });
        }
      }
    };

    const drawFrame = () => {
      tick += 0.022;
      ctx.clearRect(0, 0, width, height);

      if (variant === 'wave') {
        const grad = ctx.createRadialGradient(
          width * 0.5,
          height * 0.92,
          20,
          width * 0.5,
          height * 0.9,
          Math.max(width, height) * 0.6
        );
        if (theme === 'dark') {
          grad.addColorStop(0, 'rgba(47, 113, 227, 0.2)');
          grad.addColorStop(0.5, 'rgba(30, 82, 136, 0.1)');
          grad.addColorStop(1, 'rgba(7, 7, 8, 0)');
        } else {
          grad.addColorStop(0, 'rgba(47, 117, 195, 0.11)');
          grad.addColorStop(0.55, 'rgba(47, 117, 195, 0.04)');
          grad.addColorStop(1, 'rgba(255, 255, 255, 0)');
        }
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, width, height);
      }

      const pointer = pointerRef.current;
      const colors = theme === 'dark' ? DARK_HERO_COLORS : LIGHT_HERO_COLORS;
      const influenceRadius = variant === 'wave' ? 200 : 230;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const driftX = Math.cos(tick + p.phase) * (variant === 'wave' ? 3.2 : 4.2);
        const driftY = Math.sin(tick * 1.1 + p.phase) * (variant === 'wave' ? 3.8 : 4.2);

        let targetX = p.baseX + driftX;
        let targetY = p.baseY + driftY;

        if (pointer.active && !prefersReducedMotion) {
          const dx = pointer.x - p.x;
          const dy = pointer.y - p.y;
          const dist = Math.hypot(dx, dy);
          if (dist < influenceRadius && dist > 1) {
            const pull = (1 - dist / influenceRadius) * (variant === 'wave' ? 38 : 44);
            targetX += (dx / dist) * pull;
            targetY += (dy / dist) * pull;
          }
        }

        p.vx += (targetX - p.x) * 0.1;
        p.vy += (targetY - p.y) * 0.1;
        p.vx *= 0.8;
        p.vy *= 0.8;
        p.x += p.vx;
        p.y += p.vy;

        const color =
          variant === 'wave'
            ? theme === 'dark'
              ? i % 4 === 0
                ? '#7FB3FF'
                : '#CBD5E1'
              : i % 3 === 0
                ? '#2F75C3'
                : '#64748B'
            : colors[p.hueIndex % colors.length];

        ctx.globalAlpha = p.alpha;

        if (p.isDot || variant === 'wave') {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fill();
        } else {
          const angle = pointer.active
            ? Math.atan2(pointer.y - p.y, pointer.x - p.x)
            : Math.atan2(p.y - height * 0.44, p.x - width * 0.48);
          const halfLen = p.length * 0.5;
          const cosA = Math.cos(angle) * halfLen;
          const sinA = Math.sin(angle) * halfLen;
          ctx.strokeStyle = color;
          ctx.lineWidth = p.size;
          ctx.lineCap = 'round';
          ctx.beginPath();
          ctx.moveTo(p.x - cosA, p.y - sinA);
          ctx.lineTo(p.x + cosA, p.y + sinA);
          ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
    };

    const scheduleNextFrame = () => {
      if (disposed || prefersReducedMotion) return;
      timerId = window.setTimeout(() => {
        if (disposed) return;
        rafId = window.requestAnimationFrame(() => {
          if (disposed) return;
          if (!document.hidden) drawFrame();
          scheduleNextFrame();
        });
      }, 34);
    };

    const onMouseMove = (e: MouseEvent) => {
      pointerRef.current = {
        x: e.clientX,
        y: e.clientY,
        active: true,
      };
    };

    const onMouseLeave = () => {
      pointerRef.current.active = false;
    };

    const onResize = () => {
      initParticles();
      drawFrame();
    };

    initParticles();
    drawFrame();
    scheduleNextFrame();

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('mouseleave', onMouseLeave);
    window.addEventListener('resize', onResize);

    return () => {
      disposed = true;
      if (timerId !== null) window.clearTimeout(timerId);
      if (rafId !== null) window.cancelAnimationFrame(rafId);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseleave', onMouseLeave);
      window.removeEventListener('resize', onResize);
    };
  }, [theme, variant]);

  return (
    <canvas
      ref={canvasRef}
      data-testid={`particle-canvas-${variant}`}
      aria-hidden="true"
      className={`pointer-events-none fixed inset-0 z-0 ${className}`}
    />
  );
};
