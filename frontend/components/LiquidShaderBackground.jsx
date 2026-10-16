'use client';

import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

// Vertex Shader for the Sculpted Stippled Wave Ribbon
const waveVertexShader = `
  uniform float uTime;
  uniform vec2 uResolution;
  uniform vec2 uMouse;

  varying vec2 vUv;
  varying vec3 vNormal;
  varying vec3 vViewPosition;
  varying float vElevation;
  varying float vRibbonMask;
  varying vec2 vWorldPos;

  // 2D Simplex Noise
  vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec2 mod289(vec2 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec3 permute(vec3 x) { return mod289(((x * 34.0) + 1.0) * x); }

  float snoise(vec2 v) {
    const vec4 C = vec4(0.211324865405187, 0.366025403784439, -0.577350269189626, 0.024390243902439);
    vec2 i  = floor(v + dot(v, C.yy));
    vec2 x0 = v - i + dot(i, C.xx);
    vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
    vec4 x12 = x0.xyxy + C.xxzz;
    x12.xy -= i1;
    i = mod289(i);
    vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0)) + i.x + vec3(0.0, i1.x, 1.0));
    vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy), dot(x12.zw, x12.zw)), 0.0);
    m = m * m; m = m * m;
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

  // Wave elevation matching reference video frames:
  // - High bulbous crest arching across upper-right with soft shadow underneath
  // - Broad sweeping shoulder along the left flank
  // - Subtle saddle in the center behind the typography
  float getDisplacement(vec2 p, float t, vec2 mouse) {
    vec2 coord = p * 0.24;
    coord += mouse * 0.06;

    // Organic domain warping for soft fluid folds
    vec2 warp1 = vec2(
      snoise(coord * 0.85 + vec2(t * 0.038, t * 0.025)),
      snoise(coord * 0.75 - vec2(t * 0.032, -t * 0.021))
    );

    vec2 warp2 = vec2(
      snoise(coord * 1.1 + 0.7 * warp1 + vec2(2.8, 6.4) + t * 0.028),
      snoise(coord * 0.9 + 0.65 * warp1 + vec2(5.5, 2.1) - t * 0.022)
    );

    // 1. Right Crest: Voluptuous rounded formation arching towards upper-right
    float rightCrest = exp(-pow((p.x - 2.6 + warp2.x * 0.5) * 0.52, 2.0) - pow((p.y - 0.75 + warp2.y * 0.4) * 0.7, 2.0)) * 2.65;

    // 2. Left Bank: Rolling shoulder across left flank
    float leftBank = exp(-pow((p.x + 2.8 + warp2.y * 0.45) * 0.46, 2.0) - pow((p.y - 0.25 + warp2.x * 0.35) * 0.65, 2.0)) * 2.15;

    // 3. Central Basin: Negative space for typography
    float centerValley = -exp(-pow(p.x * 0.65, 2.0) - pow(p.y * 0.75, 2.0)) * 0.65;

    // 4. Undulating flowing waves connecting them into a continuous ribbon
    float wave1 = sin(coord.x * 1.15 + coord.y * 0.6 + t * 0.095 + warp1.x * 0.6) * 0.45;
    float wave2 = cos(coord.x * 0.8 - coord.y * 1.1 + t * 0.075 + warp1.y * 0.5) * 0.35;

    return rightCrest + leftBank + centerValley + wave1 + wave2;
  }

  void main() {
    vUv = uv;
    vWorldPos = position.xy;
    vec3 pos = position;
    float t = uTime;

    // S-curve spine: Ribbon center follows a diagonal curve across the viewport
    float spineY = sin(pos.x * 0.42 + 0.35) * 0.85 + 0.25;
    float distFromSpine = abs(pos.y - spineY);
    
    // Ribbon envelope mask: Isolates the wave into a floating organic ribbon
    float ribbonMask = exp(-pow(distFromSpine * 0.58, 2.2));
    vRibbonMask = ribbonMask;

    // Displace z based on wave elevation attenuated by ribbon envelope
    float disp = getDisplacement(pos.xy, t, uMouse) * (0.4 + 0.6 * ribbonMask);
    pos.z += disp;
    vElevation = disp;

    // Finite difference normal
    float eps = 0.035;
    float dispX = getDisplacement(pos.xy + vec2(eps, 0.0), t, uMouse) * (0.4 + 0.6 * ribbonMask);
    float dispY = getDisplacement(pos.xy + vec2(0.0, eps), t, uMouse) * (0.4 + 0.6 * ribbonMask);

    vec3 tangentX = normalize(vec3(eps, 0.0, dispX - disp));
    vec3 tangentY = normalize(vec3(0.0, eps, dispY - disp));
    vec3 calculatedNormal = normalize(cross(tangentX, tangentY));

    vNormal = normalize(normalMatrix * calculatedNormal);
    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    vViewPosition = -mvPosition.xyz;

    gl_Position = projectionMatrix * mvPosition;
  }
`;

// Fragment Shader with Light Green Studio Shading and Stochastic Edge Stipples
const waveFragmentShader = `
  uniform float uTime;
  uniform vec2 uResolution;

  varying vec2 vUv;
  varying vec3 vNormal;
  varying vec3 vViewPosition;
  varying float vElevation;
  varying float vRibbonMask;
  varying vec2 vWorldPos;

  // High-frequency pseudo-random hash for fine stipple noise
  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453123);
  }

  void main() {
    vec3 normal = normalize(vNormal);
    vec3 viewDir = normalize(vViewPosition);

    // Studio directional lighting
    vec3 keyLight = normalize(vec3(0.55, 0.72, 0.5));
    float diff1 = pow(max(dot(normal, keyLight) * 0.5 + 0.5, 0.0), 1.45);

    vec3 fillLight = normalize(vec3(-0.52, -0.22, 0.42));
    float diff2 = pow(max(dot(normal, fillLight) * 0.5 + 0.5, 0.0), 1.25) * 0.35;

    // Soft specular sheen
    vec3 halfDir = normalize(keyLight + viewDir);
    float spec = pow(max(dot(normal, halfDir), 0.0), 20.0) * 0.14;

    float light = clamp(diff1 + diff2, 0.0, 1.0);

    // Soft ambient occlusion in deep valleys
    float ao = smoothstep(-1.2, 1.8, vElevation);
    ao = mix(0.72, 1.0, ao);

    // White and Light-Gray Monochromatic Palette:
    // Deepest valley shadow: soft light-gray sculptural shadow (vec3(0.72, 0.75, 0.79))
    // Midtones: luminous soft off-white/light-gray silk (vec3(0.92, 0.94, 0.96))
    // Crest highlights: crisp brilliant white (vec3(1.0, 1.0, 1.0))
    vec3 shadowCol = vec3(0.72, 0.75, 0.79);
    vec3 midCol    = vec3(0.92, 0.94, 0.96);
    vec3 lightCol  = vec3(1.0, 1.0, 1.0);

    float lightSum = light * ao;
    vec3 surfaceColor = mix(shadowCol, midCol, smoothstep(0.12, 0.65, lightSum));
    surfaceColor = mix(surfaceColor, lightCol, smoothstep(0.65, 1.0, lightSum) + spec);

    // Micro-grain dither
    vec2 screenCoord = gl_FragCoord.xy;
    float grain = (hash(screenCoord * 0.85 + uTime * 0.02) - 0.5) * 0.035;
    surfaceColor += vec3(grain);

    // Edge Falloff:
    float edgeFadeY = smoothstep(0.04, 0.32, vUv.y) * smoothstep(0.98, 0.78, vUv.y);
    float edgeFadeX = smoothstep(0.0, 0.14, vUv.x) * smoothstep(1.0, 0.86, vUv.x);
    float envelope = vRibbonMask * edgeFadeY * edgeFadeX;

    // Stochastic Stipple Edge Dissolution
    float stippleThreshold = hash(screenCoord * 1.25);
    if (envelope < 0.28 && stippleThreshold > envelope / 0.28) {
      discard;
    }

    float finalAlpha = smoothstep(0.0, 0.35, envelope);

    // Seamless blend with canvas #f8fafc
    vec3 bgCanvasCol = vec3(0.973, 0.980, 0.988); // #f8fafc
    vec3 finalColor = mix(bgCanvasCol, surfaceColor, finalAlpha * 0.94);

    gl_FragColor = vec4(finalColor, 1.0);
  }
`;

// Floating Ambient Sand / Dust Grains Shaders
const dustVertexShader = `
  uniform float uTime;
  uniform float uDpr;
  attribute float aSize;
  attribute float aSeed;
  varying float vAlpha;

  void main() {
    vec3 pos = position;
    float t = uTime * 0.14;

    // Smooth 3D curl drifting around the crest
    pos.x += sin(t * 0.8 + aSeed * 6.28) * 0.45;
    pos.y += cos(t * 0.9 + aSeed * 4.15) * 0.4;
    pos.z += sin(t * 0.6 + aSeed * 8.31) * 0.5;

    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    gl_Position = projectionMatrix * mvPosition;

    gl_PointSize = aSize * (1.0 / -mvPosition.z) * 16.0 * (uDpr * 0.85);
    gl_PointSize = clamp(gl_PointSize, 1.2, 5.5);

    // Subtle breathing alpha
    vAlpha = 0.35 + 0.35 * sin(uTime * 0.6 + aSeed * 10.0);
  }
`;

const dustFragmentShader = `
  varying float vAlpha;
  void main() {
    vec2 coord = gl_PointCoord - vec2(0.5);
    float d = length(coord);
    if (d > 0.5) discard;
    float a = smoothstep(0.5, 0.15, d) * vAlpha;
    // Subtle monochromatic charcoal/graphite dust grains matching reference recording
    gl_FragColor = vec4(0.35, 0.38, 0.42, a * 0.45);
  }
`;

export default function LiquidShaderBackground({ className = '' }) {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Scene
    const scene = new THREE.Scene();

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || 750;

    // Camera setup: broad perspective viewing the sculpted floating ribbon
    const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 100);
    camera.position.set(0, -0.28, 5.6);
    camera.lookAt(0, 0.22, 0);

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

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    renderer.setPixelRatio(dpr);
    renderer.setSize(width, height);
    renderer.setClearColor(0xf8fafc, 1.0); // Clean subtle off-white #f8fafc
    renderer.domElement.style.position = 'absolute';
    renderer.domElement.style.top = '0';
    renderer.domElement.style.left = '0';
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.pointerEvents = 'none';

    container.appendChild(renderer.domElement);

    // Uniforms
    const uniforms = {
      uTime: { value: 0 },
      uResolution: { value: new THREE.Vector2(width, height) },
      uMouse: { value: new THREE.Vector2(0, 0) },
      uDpr: { value: dpr },
    };

    // 1. Sculpted Wave Ribbon Mesh with Stochastic Stipple Edge Dissolution
    const waveGeo = new THREE.PlaneGeometry(10.2, 6.4, 260, 180);
    const waveMat = new THREE.ShaderMaterial({
      vertexShader: waveVertexShader,
      fragmentShader: waveFragmentShader,
      uniforms: uniforms,
      side: THREE.DoubleSide,
    });
    const waveMesh = new THREE.Mesh(waveGeo, waveMat);
    scene.add(waveMesh);

    // 2. Floating Ambient Dust / Sand Grains (2,400 monochromatic graphite particles)
    const dustCount = 2400;
    const dustGeo = new THREE.BufferGeometry();
    const dustPositions = new Float32Array(dustCount * 3);
    const dustSizes = new Float32Array(dustCount);
    const dustSeeds = new Float32Array(dustCount);

    for (let i = 0; i < dustCount; i++) {
      const px = (Math.random() - 0.48) * 9.2;
      const spineY = Math.sin(px * 0.42 + 0.35) * 0.85 + 0.25;
      const py = spineY + (Math.random() - 0.5) * 2.8;
      const pz = (Math.random() - 0.15) * 2.5;

      dustPositions[i * 3 + 0] = px;
      dustPositions[i * 3 + 1] = py;
      dustPositions[i * 3 + 2] = pz;

      dustSizes[i] = 1.0 + Math.random() * 2.0;
      dustSeeds[i] = Math.random();
    }

    dustGeo.setAttribute('position', new THREE.BufferAttribute(dustPositions, 3));
    dustGeo.setAttribute('aSize', new THREE.BufferAttribute(dustSizes, 1));
    dustGeo.setAttribute('aSeed', new THREE.BufferAttribute(dustSeeds, 1));

    const dustMat = new THREE.ShaderMaterial({
      vertexShader: dustVertexShader,
      fragmentShader: dustFragmentShader,
      uniforms: uniforms,
      transparent: true,
      depthWrite: false,
      blending: THREE.NormalBlending,
    });
    const dustMesh = new THREE.Points(dustGeo, dustMat);
    scene.add(dustMesh);

    // Mouse Interaction
    const targetMouse = new THREE.Vector2(0, 0);
    const currentMouse = new THREE.Vector2(0, 0);

    const handleMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      targetMouse.set(x, y);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });

    // Handle Resize
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
      uniforms.uResolution.value.set(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    // Dynamic reduced motion preference listener
    const motionMediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    let reducedMotion = motionMediaQuery.matches;
    const handleMotionChange = (e) => {
      reducedMotion = e.matches;
    };
    motionMediaQuery.addEventListener('change', handleMotionChange);

    // Visibility Management
    let isVisible = true;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          isVisible = entry.isIntersecting;
        });
      },
      { threshold: 0.05 }
    );
    observer.observe(container);

    // Animation Loop
    let animationFrameId;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);

      if (!isVisible) return;

      const delta = clock.getDelta();

      if (!reducedMotion) {
        uniforms.uTime.value += delta * 0.45;
      }

      currentMouse.x += (targetMouse.x - currentMouse.x) * 0.045;
      currentMouse.y += (targetMouse.y - currentMouse.y) * 0.045;
      uniforms.uMouse.value.copy(currentMouse);

      camera.position.x = currentMouse.x * 0.16;
      camera.position.y = -0.28 + currentMouse.y * 0.12;
      camera.lookAt(0, 0.22, 0);

      renderer.render(scene, camera);
    };

    animate();

    // Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      motionMediaQuery.removeEventListener('change', handleMotionChange);
      observer.disconnect();

      if (renderer.domElement && renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }

      waveGeo.dispose();
      waveMat.dispose();
      dustGeo.dispose();
      dustMat.dispose();
      renderer.dispose();
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={`liquid-shader-container ${className}`}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        overflow: 'hidden',
        pointerEvents: 'none',
      }}
      aria-hidden="true"
    />
  );
}
