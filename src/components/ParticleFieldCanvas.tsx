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
}

const LIGHT_HERO_COLORS = ['#2F75C3', '#4F46E5', '#2563EB', '#E11D48', '#D97706', '#0A0A0C'];
const DARK_HERO_COLORS = ['#2F71E3', '#60A5FA', '#93C5FD', '#E2E8F0', '#FFFFFF'];

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
    let tick = 0;

    const initParticles = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 2);

      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      particles = [];

      if (variant === 'wave') {
        const cols = width < 640 ? 20 : 30;
        const rows = width < 640 ? 8 : 11;
        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols; c++) {
            const nx = (c + 0.5) / cols;
            const ny = 0.54 + (r / rows) * 0.44;
            const waveOffset = Math.sin(nx * Math.PI * 3 + r * 0.45) * 18;
            const bx = nx * width;
            const by = ny * height + waveOffset;
            particles.push({
              baseX: bx,
              baseY: by,
              x: bx,
              y: by,
              vx: 0,
              vy: 0,
              size: 1.5 + ((r + c) % 3) * 0.55,
              length: 2,
              phase: nx * 6.28 + r * 0.5,
              hueIndex: (r * 3 + c) % 5,
              alpha: 0.25 + (r / rows) * 0.5,
            });
          }
        }
      } else {
        // Hero orbital constellation radiating outward and following cursor
        const count = width < 640 ? 95 : 175;
        const cx = width * 0.36;
        const cy = height * 0.55;
        const maxRadius = Math.max(width, height) * 0.72;
        for (let i = 0; i < count; i++) {
          const frac = (i + 1) / count;
          const angle = i * 2.3999632; // Golden angle spiral
          const radius = 55 + Math.sqrt(frac) * maxRadius;
          const bx = cx + Math.cos(angle) * radius;
          const by = cy + Math.sin(angle) * radius * 0.78;
          particles.push({
            baseX: bx,
            baseY: by,
            x: bx,
            y: by,
            vx: 0,
            vy: 0,
            size: 1.7 + (i % 3) * 0.45,
            length: 4 + (i % 5) * 1.4,
            phase: angle,
            hueIndex: i % 6,
            alpha: 0.35 + (i % 4) * 0.14,
          });
        }
      }
    };

    const drawFrame = () => {
      tick += 0.014;
      ctx.clearRect(0, 0, width, height);

      if (variant === 'wave') {
        // Subtle atmospheric horizon glow matching Antigravity login aesthetic
        const grad = ctx.createRadialGradient(
          width * 0.55,
          height * 0.92,
          20,
          width * 0.5,
          height * 0.9,
          Math.max(width, height) * 0.62
        );
        if (theme === 'dark') {
          grad.addColorStop(0, 'rgba(47, 113, 227, 0.24)');
          grad.addColorStop(0.45, 'rgba(30, 82, 136, 0.14)');
          grad.addColorStop(1, 'rgba(7, 7, 8, 0)');
        } else {
          grad.addColorStop(0, 'rgba(47, 117, 195, 0.14)');
          grad.addColorStop(0.55, 'rgba(47, 117, 195, 0.05)');
          grad.addColorStop(1, 'rgba(255, 255, 255, 0)');
        }
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, width, height);
      }

      const pointer = pointerRef.current;
      const colors = theme === 'dark' ? DARK_HERO_COLORS : LIGHT_HERO_COLORS;
      const influenceRadius = variant === 'wave' ? 210 : 240;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const driftX = Math.cos(tick + p.phase) * (variant === 'wave' ? 4 : 6);
        const driftY = Math.sin(tick * 1.15 + p.phase) * (variant === 'wave' ? 5 : 6);

        let targetX = p.baseX + driftX;
        let targetY = p.baseY + driftY;

        if (pointer.active && !prefersReducedMotion) {
          const dx = pointer.x - p.x;
          const dy = pointer.y - p.y;
          const dist = Math.hypot(dx, dy);
          if (dist < influenceRadius && dist > 1) {
            const pull = (1 - dist / influenceRadius) * (variant === 'wave' ? 44 : 52);
            targetX += (dx / dist) * pull;
            targetY += (dy / dist) * pull;
          }
        }

        p.vx += (targetX - p.x) * 0.075;
        p.vy += (targetY - p.y) * 0.075;
        p.vx *= 0.82;
        p.vy *= 0.82;
        p.x += p.vx;
        p.y += p.vy;

        const color =
          variant === 'wave'
            ? theme === 'dark'
              ? i % 4 === 0
                ? '#7FB3FF'
                : '#FFFFFF'
              : i % 3 === 0
                ? '#2F75C3'
                : '#475569'
            : colors[p.hueIndex % colors.length];

        ctx.save();
        ctx.globalAlpha = p.alpha;
        ctx.fillStyle = color;
        ctx.strokeStyle = color;

        if (variant === 'wave') {
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fill();
        } else {
          // Crisp Antigravity directional micro-dash oriented toward pointer or center
          const angle = pointer.active
            ? Math.atan2(pointer.y - p.y, pointer.x - p.x)
            : Math.atan2(p.y - height * 0.55, p.x - width * 0.36);
          ctx.translate(p.x, p.y);
          ctx.rotate(angle);
          ctx.lineWidth = p.size;
          ctx.lineCap = 'round';
          ctx.beginPath();
          ctx.moveTo(-p.length * 0.5, 0);
          ctx.lineTo(p.length * 0.5, 0);
          ctx.stroke();
        }
        ctx.restore();
      }
    };

    const animate = () => {
      drawFrame();
      if (!prefersReducedMotion) {
        rafId = window.requestAnimationFrame(animate);
      }
    };

    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointerRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        active: true,
      };
    };

    const onMouseLeave = () => {
      pointerRef.current.active = false;
    };

    const onResize = () => {
      initParticles();
      if (prefersReducedMotion) drawFrame();
    };

    initParticles();
    animate();

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('mouseleave', onMouseLeave);
    window.addEventListener('resize', onResize);

    return () => {
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
