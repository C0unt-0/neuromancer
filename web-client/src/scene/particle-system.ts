// ═══════════════════════════════════════════════════
//  CYBERDECK — Particle System
//  Animated packets traveling along edges to visualize
//  live network traffic
// ═══════════════════════════════════════════════════

import * as THREE from "three";
import { PROTOCOL_COLORS } from "../config.js";
import type { NodeRenderer } from "./node-renderer.js";

interface Particle {
  mesh: THREE.Mesh;
  start: THREE.Vector3;
  end: THREE.Vector3;
  t: number;       // Interpolation parameter [0, 1]
  speed: number;   // Units per second
}

const MAX_PARTICLES = 1500;

// Shared geometry for all particles
const particleGeo = new THREE.SphereGeometry(0.6, 8, 8);

export class ParticleSystem {
  private scene: THREE.Scene;
  private nodeRenderer: NodeRenderer;
  private particles: Particle[] = [];

  constructor(scene: THREE.Scene, nodeRenderer: NodeRenderer) {
    this.scene = scene;
    this.nodeRenderer = nodeRenderer;
  }

  /**
   * Emit a particle traveling from source to destination.
   */
  emit(srcIp: string, dstIp: string, protocol: string): void {
    if (this.particles.length >= MAX_PARTICLES) return;

    const srcPos = this.nodeRenderer.getPosition(srcIp);
    const dstPos = this.nodeRenderer.getPosition(dstIp);
    if (!srcPos || !dstPos) return;

    const colorHex = PROTOCOL_COLORS[protocol] ?? "#ffffff";
    const color = new THREE.Color(colorHex);

    const mat = new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.9,
    });

    const mesh = new THREE.Mesh(particleGeo, mat);
    mesh.position.copy(srcPos);
    mesh.scale.setScalar(0.4 + Math.random() * 0.3);
    this.scene.add(mesh);

    this.particles.push({
      mesh,
      start: srcPos.clone(),
      end: dstPos.clone(),
      t: 0,
      speed: 0.008 + Math.random() * 0.012,
    });
  }

  /**
   * Update all particles — call every frame.
   */
  animate(delta: number): void {
    const toRemove: number[] = [];

    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];
      p.t += p.speed;

      if (p.t >= 1) {
        // Particle reached destination — remove it
        this.scene.remove(p.mesh);
        p.mesh.geometry.dispose();
        (p.mesh.material as THREE.Material).dispose();
        toRemove.push(i);
        continue;
      }

      // Interpolate position with slight arc
      p.mesh.position.lerpVectors(p.start, p.end, p.t);
      // Add subtle Y arc for visual interest
      p.mesh.position.y += Math.sin(p.t * Math.PI) * 2;

      // Fade out near the end
      const mat = p.mesh.material as THREE.MeshBasicMaterial;
      mat.opacity = p.t > 0.8 ? (1 - p.t) * 5 : 0.9;
    }

    // Remove completed particles (in reverse order to maintain indices)
    for (let i = toRemove.length - 1; i >= 0; i--) {
      this.particles.splice(toRemove[i], 1);
    }
  }

  /**
   * Get current particle count.
   */
  getCount(): number {
    return this.particles.length;
  }

  /**
   * Clear all particles.
   */
  clear(): void {
    for (const p of this.particles) {
      this.scene.remove(p.mesh);
      (p.mesh.material as THREE.Material).dispose();
    }
    this.particles = [];
  }
}
