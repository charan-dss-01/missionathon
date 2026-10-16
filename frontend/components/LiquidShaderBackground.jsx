'use client';

import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

// Vertex Shader: Broad, large-scale, asymmetrical sculptural liquid/fabric surface
const vertexShader = `
  uniform float uTime;
  uniform vec2 uResolution;

  varying vec2 vUv;
  varying vec3 vNormal;
  varying vec3 vViewPosition;
  varying float vElevation;
  varying vec2 vWorldPos;

  // Stefan Gustavson Simplex 2D noise
  vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec2 mod289(vec2 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec3 permute(vec3 x) { return mod289(((x * 34.0) + 1.0) * x); }

  float snoise(vec2 v) {
    const vec4 C = vec4(0.211324865405187,
                        0.366025403784439,
                       -0.577350269189626,
                        0.024390243902439);
    vec2 i  = floor(v + dot(v, C.yy));
    vec2 x0 = v - i + dot(i, C.xx);
    vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
    vec4 x12 = x0.xyxy + C.xxzz;
    x12.xy -= i1;
    i = mod289(i);
    vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0))
          + i.x + vec3(0.0, i1.x, 1.0));
    vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy), dot(x12.zw, x12.zw)), 0.0);
    m = m * m;
    m = m * m;
    vec3 x = 2.0 * fract(p * C.www) - 1.0;
    vec3 h = abs(x) - 0.5;
    vec3 ox = floor(x + 0.5);
    vec3 a0 = x - ox;
    m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h);
    vec3 g;
    g.x  = a0.x  * x0.x  + h.x  * x0.y;
    g.yz = a0.yz * x12.xz + h.yz * x12.yw;
    return 130.0 * dot(m, g);
  }

  // Broad, sculptural wave displacement
  // Large scale formations with organic asymmetrical topology matching reference
  float getDisplacement(vec2 p, float t) {
    // Ultra-low frequency scaling for massive, sweeping sculptural forms
    vec2 coord = p * 0.18;

    // Organic domain warping for smooth liquid silk folds
    vec2 warp1 = vec2(
      snoise(coord * 0.75 + vec2(t * 0.02, t * 0.014)),
      snoise(coord * 0.65 - vec2(t * 0.016, -t * 0.011))
    );

    vec2 warp2 = vec2(
      snoise(coord * 1.05 + 0.8 * warp1 + vec2(2.1, 6.7) + 0.018 * t),
      snoise(coord * 0.85 + 0.7 * warp1 + vec2(5.8, 3.2) - 0.014 * t)
    );

    // Asymmetrical Macro Formations:
    // 1. Left sculptural ridge sweeping down the flank
    float leftWave = exp(-pow((p.x + 0.35 * p.y + 2.5 + warp2.x * 0.35) * 0.44, 2.0)) * 1.45;

    // 2. Right sweeping crest arching diagonally across top-right
    float rightWave = exp(-pow((p.x - 0.6 * p.y - 2.3 + warp2.y * 0.4) * 0.4, 2.0)) * 1.65;

    // 3. Central basin ensuring headline text remains crystal clear
    float centerBasin = -exp(-pow(p.x * 0.58, 2.0) - pow(p.y * 0.58, 2.0)) * 0.55;

    // Dynamic wave harmonics (very broad, low frequency)
    float wave1 = sin(coord.x * 0.72 + coord.y * 0.42 + t * 0.075 + warp1.x * 0.5) * 0.55;
    float wave2 = cos(coord.x * 0.52 - coord.y * 0.78 + t * 0.055 + warp1.y * 0.45) * 0.42;

    float elevation = leftWave + rightWave + centerBasin + wave1 + wave2;

    // Smooth soft curvature
    elevation = smoothstep(-1.5, 1.5, elevation) * 3.1 - 1.55;

    return elevation;
  }

  void main() {
    vUv = uv;
    vWorldPos = position.xy;

    vec3 pos = position;
    float t = uTime;

    // Displace z-coordinate
    float disp = getDisplacement(pos.xy, t);
    pos.z += disp;
    vElevation = disp;

    // Silky-smooth finite difference normals
    float eps = 0.035;
    float dispX = getDisplacement(pos.xy + vec2(eps, 0.0), t);
    float dispY = getDisplacement(pos.xy + vec2(0.0, eps), t);

    vec3 tangentX = normalize(vec3(eps, 0.0, dispX - disp));
    vec3 tangentY = normalize(vec3(0.0, eps, dispY - disp));
    vec3 calculatedNormal = normalize(cross(tangentX, tangentY));

    // View-space transformation
    vNormal = normalize(normalMatrix * calculatedNormal);
    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    vViewPosition = -mvPosition.xyz;

    gl_Position = projectionMatrix * mvPosition;
  }
`;

// Fragment Shader: Ultra-soft monochromatic studio lighting, subtle grain, seamless white fade
const fragmentShader = `
  uniform float uTime;
  uniform vec2 uResolution;

  varying vec2 vUv;
  varying vec3 vNormal;
  varying vec3 vViewPosition;
  varying float vElevation;
  varying vec2 vWorldPos;

  void main() {
    vec3 normal = normalize(vNormal);
    vec3 viewDir = normalize(vViewPosition);

    // Studio lighting:
    // Key Light: soft directional studio light from upper right
    vec3 keyLight = normalize(vec3(0.52, 0.68, 0.52));
    // Fill Light: subtle ambient fill from opposite side
    vec3 fillLight = normalize(vec3(-0.5, -0.25, 0.45));

    // Wrapped diffuse lighting for creamy, smooth transitions
    float NdotL1 = dot(normal, keyLight);
    float diff1 = pow(NdotL1 * 0.5 + 0.5, 1.35);

    float NdotL2 = dot(normal, fillLight);
    float diff2 = pow(NdotL2 * 0.5 + 0.5, 1.25) * 0.32;

    // Soft matte specular highlight (porcelain/silk sheen, gentle and broad)
    vec3 halfDir = normalize(keyLight + viewDir);
    float NdotH = max(dot(normal, halfDir), 0.0);
    float spec = pow(NdotH, 16.0) * 0.14;

    // Ambient Occlusion: soft subtle shading in valleys, never harsh or pitch black
    float ao = smoothstep(-1.5, 1.5, vElevation);
    ao = mix(0.76, 1.0, ao);

    // Refined Monochromatic Palette:
    // Deepest valley: clean, elegant neutral silver-gray #c2c6cd (0.76, 0.77, 0.80)
    // Midtones: luminous porcelain off-white #f2f4f6 (0.94, 0.945, 0.955)
    // Crest highlights: pure studio white #ffffff (1.0, 1.0, 1.0)
    vec3 shadowColor = vec3(0.75, 0.77, 0.80);
    vec3 midColor    = vec3(0.94, 0.945, 0.958);
    vec3 lightColor  = vec3(1.0, 1.0, 1.0);

    float lightSum = clamp(diff1 + diff2, 0.0, 1.0) * ao;
    vec3 surfaceColor = mix(shadowColor, midColor, smoothstep(0.12, 0.65, lightSum));
    surfaceColor = mix(surfaceColor, lightColor, smoothstep(0.65, 1.0, lightSum) + spec);

    // Subtle procedural film grain (museum-quality tactile paper/matte silk finish)
    float grain = (fract(sin(dot(gl_FragCoord.xy * 0.85 + uTime * 0.03, vec2(12.9898, 78.233))) * 43758.5453) - 0.5) * 0.035;
    surfaceColor += vec3(grain);

    // Edge falloff:
    // Dissolves seamlessly into the pure white background of the website
    // Bottom fade blends into the white page below the hero section
    float bottomFade = smoothstep(0.03, 0.36, vUv.y);
    float sideFade = smoothstep(0.0, 0.1, vUv.x) * smoothstep(1.0, 0.9, vUv.x);
    float topFade = smoothstep(1.0, 0.94, vUv.y);
    float alphaFade = bottomFade * sideFade * topFade;

    // Final color blends gracefully to pure white
    vec3 finalColor = mix(vec3(1.0, 1.0, 1.0), surfaceColor, alphaFade);

    gl_FragColor = vec4(finalColor, 1.0);
  }
`;


export default function LiquidShaderBackground({ className = '' }) {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Scene
    const scene = new THREE.Scene();

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || 750;

    // Camera setup: broad view with perspective
    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 100);
    camera.position.set(0, -0.4, 6.0);
    camera.lookAt(0, 0.25, 0);

    // WebGL Renderer
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: false,
        powerPreference: 'high-performance',
      });
    } catch (e) {
      console.warn('WebGL not supported:', e);
      return;
    }

    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0xffffff, 1);
    container.appendChild(renderer.domElement);

    // Geometry: Subdivided plane spanning the viewport
    const isMobile = width < 768;
    const segments = isMobile ? 130 : 220;
    const geometry = new THREE.PlaneGeometry(13.5, 8.2, segments, segments);

    // Shader Material
    const uniforms = {
      uTime: { value: 0.0 },
      uResolution: { value: new THREE.Vector2(width, height) },
    };

    const material = new THREE.ShaderMaterial({
      vertexShader,
      fragmentShader,
      uniforms,
      wireframe: false,
      side: THREE.DoubleSide,
    });

    const mesh = new THREE.Mesh(geometry, material);
    mesh.rotation.x = -0.36;
    mesh.rotation.z = -0.04;
    scene.add(mesh);

    // Animation Loop
    let animationFrameId;
    let isVisible = true;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);

      if (!isVisible) return;

      const delta = clock.getDelta();
      // Very slow, continuous, fluid movement (speed tuned for elegance)
      const speed = prefersReducedMotion ? 0.0 : 0.38;
      uniforms.uTime.value += delta * speed;

      renderer.render(scene, camera);
    };

    animate();

    // IntersectionObserver to pause rendering when offscreen
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          isVisible = entry.isIntersecting;
        });
      },
      { threshold: 0.05 }
    );
    observer.observe(container);

    // Page Visibility API
    const handleVisibilityChange = () => {
      isVisible = document.visibilityState === 'visible';
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Window Resize Handler
    const handleResize = () => {
      if (!container || !renderer) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;

      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();

      renderer.setSize(newWidth, newHeight);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      uniforms.uResolution.value.set(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    // WebGL Context Loss Handling
    const canvas = renderer.domElement;
    const handleContextLost = (event) => {
      event.preventDefault();
      cancelAnimationFrame(animationFrameId);
    };

    const handleContextRestored = () => {
      handleResize();
      animate();
    };

    canvas.addEventListener('webglcontextlost', handleContextLost, false);
    canvas.addEventListener('webglcontextrestored', handleContextRestored, false);

    // Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      observer.disconnect();

      canvas.removeEventListener('webglcontextlost', handleContextLost);
      canvas.removeEventListener('webglcontextrestored', handleContextRestored);

      geometry.dispose();
      material.dispose();
      renderer.dispose();

      if (container && canvas && canvas.parentNode === container) {
        container.removeChild(canvas);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={`absolute inset-0 pointer-events-none overflow-hidden select-none bg-white ${className}`}
      style={{ zIndex: 0 }}
      aria-hidden="true"
    />
  );
}
