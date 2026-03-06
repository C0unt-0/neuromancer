// ═══════════════════════════════════════════════════
//  CYBERDECK — Tron Grid
//  Two-layer grid floor (fine + coarse divisions)
// ═══════════════════════════════════════════════════

import * as THREE from "three";

/**
 * Creates the cyberpunk Tron-style grid floor.
 * Two layers: fine grid (60 divisions, subtle) and coarse grid (6 divisions, brighter).
 */
export function createGrid(scene: THREE.Scene): void {
  // Fine grid — subtle subdivisions
  const fineGrid = new THREE.GridHelper(600, 60, 0x00f0ff, 0x00f0ff);
  (fineGrid.material as THREE.Material).opacity = 0.03;
  (fineGrid.material as THREE.Material).transparent = true;
  fineGrid.position.y = -50;
  scene.add(fineGrid);

  // Coarse grid — major divisions
  const coarseGrid = new THREE.GridHelper(600, 6, 0x00f0ff, 0x00f0ff);
  (coarseGrid.material as THREE.Material).opacity = 0.07;
  (coarseGrid.material as THREE.Material).transparent = true;
  coarseGrid.position.y = -50;
  scene.add(coarseGrid);
}
