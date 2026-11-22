import React, { useEffect, useRef } from 'react';
import type { ThemeMode } from '../types/audit';

interface ParticleFieldCanvasProps {
  theme: ThemeMode;
  variant?: 'hero' | 'wave';
  className?: string;
}

interface Particle {
  baseAngle: number;
  orbitAngle: number;
  angularSpeed: number;
  ringNorm: number; // 0 = inner halo edge, 1 = outer edge
  isAmbient: boolean;
  ambientXRatio: number;
  ambientYRatio: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  dotRadius: number;
  dashLength: number;
  lineWidth: number;
  phase: number;
  baseAlpha: number;
  isDash: boolean;
}

interface RippleWave {
  x: number;
  y: number;
  radius: number;
  maxRadius: number;
  speed: number;
  alpha: number;
}

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}

function mixRgb(c1: Rgb, c2: Rgb, t: number): string {
  const r = Math.round(lerp(c1.r, c2.r, t));
  const g = Math.round(lerp(c1.g, c2.g, t));
  const b = Math.round(lerp(c1.b, c2.b, t));
  return `rgb(${r}, ${g}, ${b})`;
}

/**
 * Matches the exact Google Antigravity spatial color arc seen in the reference:
 * Primarily crisp Google Blue & Periwinkle/Indigo around the upper & right arcs,
 * transitioning smoothly through Plum/Rose into subtle Warm Coral/Amber on the lower-left arc.
 */
function sampleAntigravityColor(angleRad: number, isDark: boolean): string {
  // Normalize angle to [0, 1) starting from top (-PI/2), clockwise:
  // 0.00 = top, 0.25 = right, 0.50 = bottom, 0.65 = bottom-left, 0.75 = left
  const norm = (((angleRad + Math.PI * 0.5) % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2) / (Math.PI * 2);

  const blue: Rgb = isDark ? { r: 92, g: 152, b: 255 } : { r: 58, g: 118, b: 245 };
  const cobalt: Rgb = isDark ? { r: 108, g: 126, b: 255 } : { r: 78, g: 104, b: 236 };
  const indigo: Rgb = isDark ? { r: 146, g: 112, b: 245 } : { r: 118, g: 82, b: 218 };
  const rose: Rgb = isDark ? { r: 224, g: 88, b: 120 } : { r: 212, g: 64, b: 96 };
  const coral: Rgb = isDark ? { r: 232, g: 118, b: 84 } : { r: 218, g: 96, b: 64 };

  if (norm < 0.5) {
    return mixRgb(blue, cobalt, norm / 0.5);
  }
  if (norm < 0.6) {
    return mixRgb(cobalt, indigo, (norm - 0.5) / 0.1);
  }
  if (norm < 0.7) {
    return mixRgb(indigo, rose, (norm - 0.6) / 0.1);
  }
  if (norm < 0.78) {
    return mixRgb(rose, coral, (norm - 0.7) / 0.08);
  }
  return mixRgb(coral, blue, (norm - 0.78) / 0.22);
}

export const ParticleFieldCanvas: React.FC<ParticleFieldCanvasProps> = ({
  theme,
  variant = 'hero',
  className = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const pointerRef = useRef<{
    x: number;
    y: number;
    active: boolean;
    isDown: boolean;
    downAt: number;
    lastPulseAt: number;
    speed: number;
  }>({
    x: 0,
    y: 0,
    active: false,
    isDown: false,
    downAt: 0,
    lastPulseAt: 0,
    speed: 0,
  });
  const wavesRef = useRef<RippleWave[]>([]);

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

    const isDark = theme === 'dark';

    const getCenter = () => ({
      cx: width * 0.5,
      cy: variant === 'wave' ? height * 0.47 : height * 0.43,
    });

    const getRadii = () => {
      const base = Math.min(width, height);
      if (variant === 'wave') {
        return {
          innerR: Math.max(145, base * 0.23),
          outerR: Math.max(295, base * 0.56),
        };
      }
      return {
        innerR: Math.max(165, base * 0.27),
        outerR: Math.max(330, base * 0.62),
      };
    };

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
      const { cx, cy } = getCenter();
      const { innerR, outerR } = getRadii();

      // 1. Primary circular Antigravity ring halo (crisp radial micro-dashes & points)
      const ringCount = width < 640 ? 220 : 420;
      for (let i = 0; i < ringCount; i++) {
        const frac = (i + 0.5) / ringCount;
        // Golden angle + subtle ring band distribution matching the Google Antigravity halo
        const angle = i * 2.3999632;
        const bandT = Math.pow((i % 37) / 36, 0.85);
        const r = lerp(innerR, outerR, bandT * 0.88 + frac * 0.12);

        const x = cx + Math.cos(angle) * r * 1.08;
        const y = cy + Math.sin(angle) * r * 0.94;

        particles.push({
          baseAngle: angle,
          orbitAngle: angle,
          angularSpeed: (i % 5 === 0 ? -0.35 : 1) * (0.0014 + (1 - bandT) * 0.0018),
          ringNorm: bandT,
          isAmbient: false,
          ambientXRatio: 0,
          ambientYRatio: 0,
          x,
          y,
          vx: 0,
          vy: 0,
          dotRadius: 1.05 + (i % 3) * 0.25,
          dashLength: 2.8 + (i % 4) * 0.85,
          lineWidth: 1.25 + (i % 2) * 0.35,
          phase: i * 0.41,
          baseAlpha: 0.46 + (1 - bandT * 0.45) * 0.42,
          isDash: i % 3 !== 0,
        });
      }

      // 2. Delicate outer micro-dots (subtle dust points across background)
      const ambientCount = width < 640 ? 75 : 145;
      for (let i = 0; i < ambientCount; i++) {
        // Deterministic pseudo-random scatter
        const rx = ((Math.sin(i * 12.9898) * 43758.5453) % 1 + 1) % 1;
        const ry = ((Math.sin(i * 78.233) * 19341.123) % 1 + 1) % 1;
        particles.push({
          baseAngle: i * 1.1,
          orbitAngle: i * 1.1,
          angularSpeed: 0.0005,
          ringNorm: 1,
          isAmbient: true,
          ambientXRatio: rx,
          ambientYRatio: ry,
          x: rx * width,
          y: ry * height,
          vx: 0,
          vy: 0,
          dotRadius: 0.85 + (i % 2) * 0.25,
          dashLength: 2,
          lineWidth: 1,
          phase: i * 0.7,
          baseAlpha: isDark ? 0.26 : 0.22,
          isDash: false,
        });
      }
    };

    const spawnWave = (x: number, y: number, strength = 1) => {
      const waves = wavesRef.current;
      if (waves.length > 8) waves.shift();
      waves.push({
        x,
        y,
        radius: 12,
        maxRadius: Math.max(width, height) * 0.58,
        speed: 7.2,
        alpha: 0.88 * strength,
      });
    };

    const drawFrame = () => {
      tick += 0.032;
      ctx.clearRect(0, 0, width, height);

      const pointer = pointerRef.current;
      pointer.speed *= 0.88;

      // If pointer is held down, emit continuous concentric ripple waves
      const now = performance.now();
      if (pointer.isDown && !prefersReducedMotion && now - pointer.lastPulseAt > 300) {
        pointer.lastPulseAt = now;
        spawnWave(pointer.x, pointer.y, 0.95);
      }

      const waves = wavesRef.current;
      for (let w = waves.length - 1; w >= 0; w--) {
        waves[w].radius += waves[w].speed;
        waves[w].alpha *= 0.968;
        if (waves[w].radius > waves[w].maxRadius || waves[w].alpha < 0.03) {
          waves.splice(w, 1);
        }
      }

      const { cx, cy } = getCenter();
      const { innerR, outerR } = getRadii();
      const hoverRadius = 210;

      // Subtle atmospheric soft radial glow ONLY on active cursor hover or wave press
      if (pointer.active && !prefersReducedMotion) {
        const auraR = pointer.isDown ? 230 : 170;
        const glow = ctx.createRadialGradient(pointer.x, pointer.y, 4, pointer.x, pointer.y, auraR);
        glow.addColorStop(0, isDark ? 'rgba(88, 148, 255, 0.12)' : 'rgba(66, 133, 244, 0.075)');
        glow.addColorStop(1, isDark ? 'rgba(7, 7, 8, 0)' : 'rgba(255, 255, 255, 0)');
        ctx.fillStyle = glow;
        ctx.fillRect(0, 0, width, height);
      }

      const neutralDotColor = isDark ? 'rgba(148, 163, 184, 0.55)' : 'rgba(100, 116, 139, 0.42)';

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        let targetX: number;
        let targetY: number;

        if (p.isAmbient) {
          targetX = p.ambientXRatio * width + Math.sin(tick * 0.5 + p.phase) * 4;
          targetY = p.ambientYRatio * height + Math.cos(tick * 0.5 + p.phase) * 4;
        } else {
          // Gentle circular ring orbit + breathing radial wave
          p.orbitAngle += p.angularSpeed;
          const waveRipple = Math.sin(p.orbitAngle * 3 - tick * 1.4 + p.phase * 0.15) * 14;
          const r = lerp(innerR, outerR, p.ringNorm) + waveRipple;

          // Subtle shift toward pointer when hovering so ring responds organically like Antigravity
          const driftX = pointer.active ? (pointer.x - cx) * 0.055 * (1 - p.ringNorm * 0.4) : 0;
          const driftY = pointer.active ? (pointer.y - cy) * 0.055 * (1 - p.ringNorm * 0.4) : 0;

          targetX = cx + driftX + Math.cos(p.orbitAngle) * r * 1.08;
          targetY = cy + driftY + Math.sin(p.orbitAngle) * r * 0.94;
        }

        let forceX = (targetX - p.x) * 0.14;
        let forceY = (targetY - p.y) * 0.14;
        let boostAlpha = p.baseAlpha;
        let waveStretch = 0;

        // Cursor hover: smooth magnetic wave displacement around cursor
        if (pointer.active && !prefersReducedMotion) {
          const dx = p.x - pointer.x;
          const dy = p.y - pointer.y;
          const dist = Math.hypot(dx, dy);
          if (dist < hoverRadius && dist > 1) {
            const strength = 1 - dist / hoverRadius;
            const ux = dx / dist;
            const uy = dy / dist;
            // Gentle repulsion + circular swirl tangential force around cursor
            const swirl = (pointer.isDown ? 5.2 : 2.8 + Math.min(4, pointer.speed * 0.12)) * strength;
            const push = (pointer.isDown ? -2.2 : 2.6) * strength;
            forceX += ux * push - uy * swirl;
            forceY += uy * push + ux * swirl;
            boostAlpha = Math.min(0.95, p.baseAlpha + strength * 0.35);
            waveStretch += strength * 2.2;
          }
        }

        // Press-triggered expanding circular waves!
        for (let w = 0; w < waves.length; w++) {
          const wave = waves[w];
          const dx = p.x - wave.x;
          const dy = p.y - wave.y;
          const dist = Math.hypot(dx, dy);
          const band = 72;
          const diff = Math.abs(dist - wave.radius);
          if (diff < band && dist > 1) {
            const crest = Math.cos((diff / band) * Math.PI * 0.5) * wave.alpha;
            const ux = dx / dist;
            const uy = dy / dist;
            forceX += ux * crest * 7.8;
            forceY += uy * crest * 7.8;
            boostAlpha = Math.min(1, boostAlpha + crest * 0.48);
            waveStretch += crest * 3.8;
          }
        }

        p.vx = (p.vx + forceX) * 0.78;
        p.vy = (p.vy + forceY) * 0.78;
        p.x += p.vx;
        p.y += p.vy;

        // Keep inner center area softly clear so text remains crystal sharp
        if (!p.isAmbient) {
          const textClearDist = Math.hypot((p.x - cx) / Math.max(150, width * 0.2), (p.y - cy) / Math.max(100, height * 0.16));
          if (textClearDist < 1) {
            boostAlpha *= Math.max(0.14, textClearDist * 0.75);
          }
        }

        ctx.globalAlpha = boostAlpha;

        if (p.isAmbient && waveStretch < 0.4) {
          ctx.fillStyle = neutralDotColor;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.dotRadius, 0, Math.PI * 2);
          ctx.fill();
        } else {
          // Sample exact Antigravity spatial gradient based on position around the ring center
          const spatialAngle = Math.atan2(p.y - cy, p.x - cx) + tick * 0.08;
          const color = sampleAntigravityColor(spatialAngle, isDark);

          if (p.isDash) {
            // Radial orientation from ring center (matches the crisp radial dashes in Antigravity screenshots)
            const radialAngle = Math.atan2(p.y - cy, p.x - cx);
            const halfLen = (p.dashLength + waveStretch) * 0.5;
            const cosA = Math.cos(radialAngle) * halfLen;
            const sinA = Math.sin(radialAngle) * halfLen;
            ctx.strokeStyle = color;
            ctx.lineWidth = p.lineWidth;
            ctx.lineCap = 'round';
            ctx.beginPath();
            ctx.moveTo(p.x - cosA, p.y - sinA);
            ctx.lineTo(p.x + cosA, p.y + sinA);
            ctx.stroke();
          } else {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.dotRadius + waveStretch * 0.14, 0, Math.PI * 2);
            ctx.fill();
          }
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
      pointerRef.current.x = x;
      pointerRef.current.y = y;
      pointerRef.current.active = true;
      pointerRef.current.speed = Math.min(40, moveDist);
    };

    const onPointerMove = (e: PointerEvent) => {
      updatePointer(e.clientX, e.clientY);
    };

    const onPointerDown = (e: PointerEvent) => {
      updatePointer(e.clientX, e.clientY);
      pointerRef.current.isDown = true;
      pointerRef.current.downAt = performance.now();
      pointerRef.current.lastPulseAt = performance.now();
      if (!prefersReducedMotion) {
        spawnWave(e.clientX, e.clientY, 1);
      }
    };

    const onPointerUp = () => {
      pointerRef.current.isDown = false;
    };

    const onTouchStart = (e: TouchEvent) => {
      const t = e.touches[0];
      if (t) {
        updatePointer(t.clientX, t.clientY);
        pointerRef.current.isDown = true;
        pointerRef.current.lastPulseAt = performance.now();
        if (!prefersReducedMotion) {
          spawnWave(t.clientX, t.clientY, 1);
        }
      }
    };

    const onTouchMove = (e: TouchEvent) => {
      const t = e.touches[0];
      if (t) updatePointer(t.clientX, t.clientY);
    };

    const onTouchEnd = () => {
      pointerRef.current.isDown = false;
    };

    const onPointerLeave = () => {
      pointerRef.current.active = false;
      pointerRef.current.isDown = false;
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
    window.addEventListener('pointerdown', onPointerDown, { passive: true });
    window.addEventListener('pointerup', onPointerUp, { passive: true });
    window.addEventListener('touchstart', onTouchStart, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    window.addEventListener('touchend', onTouchEnd, { passive: true });
    window.addEventListener('mouseleave', onPointerLeave);
    window.addEventListener('resize', onResize);

    return () => {
      disposed = true;
      if (rafId !== null) window.cancelAnimationFrame(rafId);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('touchstart', onTouchStart);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('touchend', onTouchEnd);
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
