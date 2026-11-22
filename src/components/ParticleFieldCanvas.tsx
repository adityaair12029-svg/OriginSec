import React, { useEffect, useRef } from 'react';
import type { ThemeMode } from '../types/audit';

interface ParticleFieldCanvasProps {
  theme: ThemeMode;
  variant?: 'hero' | 'wave';
  className?: string;
}

interface Particle {
  orbitRadiusX: number;
  orbitRadiusY: number;
  orbitAngle: number;
  angularSpeed: number;
  centerXRatio: number;
  centerYRatio: number;
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

// Vivid Google-brand palette engineered to pop crisply on both Light (#FFFFFF) and Dark (#070708)
const LIGHT_GOOGLE_COLORS = ['#2563EB', '#EA4335', '#D97706', '#16A34A', '#4285F4'];
const DARK_GOOGLE_COLORS = ['#4285F4', '#FF5247', '#FBBC05', '#34A853', '#60A5FA'];

export const ParticleFieldCanvas: React.FC<ParticleFieldCanvasProps> = ({
  theme,
  variant = 'hero',
  className = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const pointerRef = useRef<{ x: number; y: number; active: boolean; speed: number }>({
    x: 0,
    y: 0,
    active: false,
    speed: 0,
  });

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
        // Dense circular vortex rings & glowing dust horizon on Login page
        const count = width < 640 ? 220 : 440;
        const cx = width * 0.5;
        const cy = height * 0.62;
        const minR = Math.min(width, height) * 0.14;
        const maxR = Math.max(width, height) * 0.62;

        for (let i = 0; i < count; i++) {
          const frac = (i + 1) / count;
          const angle = i * 2.3999632;
          const radius = minR + Math.pow(frac, 0.72) * (maxR - minR);
          const rx = radius * 1.15;
          const ry = radius * 0.68;
          const bx = cx + Math.cos(angle) * rx;
          const by = cy + Math.sin(angle) * ry;

          const textCx = width * 0.5;
          const textCy = height * 0.43;
          const textDistRatio = Math.hypot((bx - textCx) / Math.max(140, width * 0.22), (by - textCy) / Math.max(95, height * 0.16));
          const textClearance = Math.min(1, Math.max(0.24, textDistRatio * 0.85));

          particles.push({
            orbitRadiusX: rx,
            orbitRadiusY: ry,
            orbitAngle: angle,
            angularSpeed: (i % 2 === 0 ? 1 : -0.65) * (0.0038 + (1 - frac) * 0.0052),
            centerXRatio: 0.5,
            centerYRatio: 0.62,
            baseX: bx,
            baseY: by,
            x: bx,
            y: by,
            vx: 0,
            vy: 0,
            size: 1.85 + (i % 3) * 0.65,
            length: 4 + (i % 3) * 1.6,
            phase: angle,
            hueIndex: i % 5,
            alpha: (0.66 + (i % 4) * 0.085) * textClearance,
            isDot: i % 4 !== 0,
          });
        }
      } else {
        // Rich, tight circular orbiting dust vortex framing the main Scanner hero & input bar
        const count = width < 640 ? 250 : 500;
        const cx = width * 0.5;
        const cy = height * 0.44;
        const minRadius = Math.min(width, height) * 0.12;
        const maxRadius = Math.max(width, height) * 0.56;

        for (let i = 0; i < count; i++) {
          const frac = (i + 1) / count;
          const angle = i * 2.3999632; // Golden-angle circular distribution
          const radius = minRadius + Math.pow(frac, 0.76) * (maxRadius - minRadius);
          const rx = radius * 1.06;
          const ry = radius * 0.84;
          const bx = cx + Math.cos(angle) * rx;
          const by = cy + Math.sin(angle) * ry;

          // Keep center behind H1 clean while making inner/mid rings crisp & unmissable
          const distRatio = Math.hypot((bx - cx) / (width * 0.28), (by - cy) / (height * 0.28));
          const centerFade = Math.min(1, Math.max(0.38, distRatio * 0.92));

          particles.push({
            orbitRadiusX: rx,
            orbitRadiusY: ry,
            orbitAngle: angle,
            angularSpeed: (i % 3 === 0 ? -0.75 : 1) * (0.0042 + (1 - frac) * 0.0062),
            centerXRatio: 0.5,
            centerYRatio: 0.44,
            baseX: bx,
            baseY: by,
            x: bx,
            y: by,
            vx: 0,
            vy: 0,
            size: 1.9 + (i % 3) * 0.65,
            length: 4.5 + (i % 4) * 1.6,
            phase: angle,
            hueIndex: i % 5,
            alpha: (0.64 + (i % 4) * 0.085) * centerFade,
            isDot: i % 3 !== 0,
          });
        }
      }
    };

    const drawFrame = () => {
      tick += 0.045;
      ctx.clearRect(0, 0, width, height);

      const pointer = pointerRef.current;
      pointer.speed *= 0.9;

      // Subtle atmospheric aura centered behind the cursor when active
      if (pointer.active && !prefersReducedMotion) {
        const glow = ctx.createRadialGradient(pointer.x, pointer.y, 4, pointer.x, pointer.y, 240);
        if (theme === 'dark') {
          glow.addColorStop(0, 'rgba(66, 133, 244, 0.16)');
          glow.addColorStop(0.5, 'rgba(52, 168, 83, 0.06)');
          glow.addColorStop(1, 'rgba(7, 7, 8, 0)');
        } else {
          glow.addColorStop(0, 'rgba(66, 133, 244, 0.11)');
          glow.addColorStop(0.5, 'rgba(234, 67, 53, 0.04)');
          glow.addColorStop(1, 'rgba(255, 255, 255, 0)');
        }
        ctx.fillStyle = glow;
        ctx.fillRect(0, 0, width, height);
      }

      const colors = theme === 'dark' ? DARK_GOOGLE_COLORS : LIGHT_GOOGLE_COLORS;
      const influenceRadius = variant === 'wave' ? 240 : 270;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        // True circular/elliptical orbital dust revolution
        p.orbitAngle += p.angularSpeed;
        const cx = width * p.centerXRatio;
        const cy = height * p.centerYRatio;
        const radialPulse = 1 + Math.sin(tick * 0.85 + p.phase) * 0.035;
        const targetX = cx + Math.cos(p.orbitAngle) * p.orbitRadiusX * radialPulse;
        const targetY = cy + Math.sin(p.orbitAngle) * p.orbitRadiusY * radialPulse;

        let forceX = (targetX - p.x) * 0.14;
        let forceY = (targetY - p.y) * 0.14;
        let boostAlpha = p.alpha;
        let boostSize = p.size;

        // Energetic circular cursor vortex: pulls & spins dust fast around the pointer
        if (pointer.active && !prefersReducedMotion) {
          const dx = pointer.x - p.x;
          const dy = pointer.y - p.y;
          const dist = Math.hypot(dx, dy);
          if (dist < influenceRadius && dist > 1) {
            const strength = 1 - dist / influenceRadius;
            const invDist = 1 / dist;
            const ux = dx * invDist;
            const uy = dy * invDist;
            // Tangential vector (-uy, ux) produces crisp circular swirling vortex around cursor
            const swirlPower = (9.5 + Math.min(10, pointer.speed * 0.25)) * strength;
            const radialPull = 6.2 * strength;

            forceX += ux * radialPull - uy * swirlPower;
            forceY += uy * radialPull + ux * swirlPower;
            boostAlpha = Math.min(1, p.alpha + strength * 0.35);
            boostSize = p.size + strength * 1.1;
          }
        }

        p.vx = (p.vx + forceX) * 0.78;
        p.vy = (p.vy + forceY) * 0.78;
        p.x += p.vx;
        p.y += p.vy;

        const color = colors[p.hueIndex % colors.length];
        ctx.globalAlpha = boostAlpha;

        if (p.isDot) {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(p.x, p.y, boostSize, 0, Math.PI * 2);
          ctx.fill();
        } else {
          // Align orbital micro-dash along live motion vector for dynamic speed trails
          const motionAngle =
            Math.hypot(p.vx, p.vy) > 0.35
              ? Math.atan2(p.vy, p.vx)
              : p.orbitAngle + Math.PI * 0.5;
          const halfLen = (p.length + Math.min(6, Math.hypot(p.vx, p.vy) * 0.7)) * 0.5;
          const cosA = Math.cos(motionAngle) * halfLen;
          const sinA = Math.sin(motionAngle) * halfLen;
          ctx.strokeStyle = color;
          ctx.lineWidth = boostSize;
          ctx.lineCap = 'round';
          ctx.beginPath();
          ctx.moveTo(p.x - cosA, p.y - sinA);
          ctx.lineTo(p.x + cosA, p.y + sinA);
          ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
    };

    const animate = () => {
      if (disposed) return;
      if (!document.hidden) {
        drawFrame();
      }
      if (!prefersReducedMotion) {
        rafId = window.requestAnimationFrame(animate);
      }
    };

    const updatePointer = (x: number, y: number) => {
      const prev = pointerRef.current;
      const moveDist = prev.active ? Math.hypot(x - prev.x, y - prev.y) : 0;
      pointerRef.current = {
        x,
        y,
        active: true,
        speed: Math.min(45, moveDist),
      };
    };

    const onPointerMove = (e: PointerEvent) => {
      updatePointer(e.clientX, e.clientY);
    };

    const onTouchMove = (e: TouchEvent) => {
      const t = e.touches[0];
      if (t) updatePointer(t.clientX, t.clientY);
    };

    const onPointerLeave = () => {
      pointerRef.current.active = false;
    };

    const onResize = () => {
      initParticles();
      drawFrame();
    };

    initParticles();
    drawFrame();
    if (!prefersReducedMotion) {
      rafId = window.requestAnimationFrame(animate);
    }

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    window.addEventListener('mouseleave', onPointerLeave);
    window.addEventListener('resize', onResize);

    return () => {
      disposed = true;
      if (rafId !== null) window.cancelAnimationFrame(rafId);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('mouseleave', onPointerLeave);
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
