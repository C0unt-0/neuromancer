// ═══════════════════════════════════════════════════
//  CYBERDECK — Node Renderer
//  Type-specific 3D geometry, emissive materials,
//  glow rings, and selection rings
// ═══════════════════════════════════════════════════

import * as THREE from "three";
import type { ClientNode, Vec3 } from "../types.js";
import { NODE_COLORS } from "../config.js";

// ── Shared Geometries (instanced for performance) ──

const geoTarget = new THREE.IcosahedronGeometry(3.5, 2);
const geoRouter = new THREE.OctahedronGeometry(3, 0);
const geoLocal = new THREE.IcosahedronGeometry(2, 1);
const geoDns = new THREE.TetrahedronGeometry(2, 0);
const geoCdn = new THREE.BoxGeometry(2.5, 2.5, 2.5);
const geoRemote = new THREE.IcosahedronGeometry(1.2, 1);

function getNodeGeometry(type: string): THREE.BufferGeometry {
  switch (type) {
    case "target": return geoTarget;
    case "router":
    case "gateway": return geoRouter;
    case "local": return geoLocal;
    case "dns": return geoDns;
    case "cdn": return geoCdn;
    default: return geoRemote;
  }
}

function getNodeColor(type: string): THREE.Color {
  const hex = NODE_COLORS[type] ?? 0xff00c8;
  return new THREE.Color(hex);
}

export interface NodeMeshData {
  mesh: THREE.Mesh;
  ring: THREE.Mesh;
  selRing: THREE.Mesh;
  nodeData: ClientNode;
  baseEmissive: number;
}

export class NodeRenderer {
  private scene: THREE.Scene;
  private nodeMeshes: Map<string, NodeMeshData> = new Map();

  constructor(scene: THREE.Scene) {
    this.scene = scene;
  }

  /**
   * Add a node to the 3D scene with type-specific geometry.
   */
  addNode(node: ClientNode): NodeMeshData | null {
    if (this.nodeMeshes.has(node.id)) return this.nodeMeshes.get(node.id)!;

    const color = getNodeColor(node.nodeType);
    const isTarget = node.nodeType === "target";
    const emissiveIntensity = isTarget ? 0.9 : 0.6;

    // Main mesh
    const mat = new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity,
      metalness: 0.8,
      roughness: 0.2,
      transparent: true,
      opacity: 0.9,
    });
    const mesh = new THREE.Mesh(getNodeGeometry(node.nodeType), mat);

    // Position — use existing position or compute golden angle layout
    if (node.position) {
      mesh.position.set(node.position.x, node.position.y, node.position.z);
    } else {
      const pos = this.computeInitialPosition(node);
      mesh.position.set(pos.x, pos.y, pos.z);
    }

    // Glow ring
    const ringRadius = isTarget ? 4 : 2.5;
    const ringGeo = new THREE.RingGeometry(ringRadius, ringRadius + (isTarget ? 1 : 0.5), 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.15,
      side: THREE.DoubleSide,
    });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    mesh.add(ring);

    // Selection ring (hidden by default)
    const selRadius = isTarget ? 5.5 : 3.5;
    const selRingGeo = new THREE.RingGeometry(selRadius, selRadius + 0.5, 32);
    const selRingMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0,
      side: THREE.DoubleSide,
    });
    const selRing = new THREE.Mesh(selRingGeo, selRingMat);
    mesh.add(selRing);

    // Store reference data
    mesh.userData = { nodeId: node.id, nodeType: node.nodeType };

    this.scene.add(mesh);

    const data: NodeMeshData = {
      mesh,
      ring,
      selRing,
      nodeData: node,
      baseEmissive: emissiveIntensity,
    };
    this.nodeMeshes.set(node.id, data);
    return data;
  }

  /**
   * Remove a node from the scene.
   */
  removeNode(nodeId: string): void {
    const data = this.nodeMeshes.get(nodeId);
    if (data) {
      this.scene.remove(data.mesh);
      data.mesh.geometry.dispose();
      (data.mesh.material as THREE.Material).dispose();
      this.nodeMeshes.delete(nodeId);
    }
  }

  /**
   * Update a node's visual state (position, staleness, etc.)
   */
  updateNode(node: ClientNode): void {
    const data = this.nodeMeshes.get(node.id);
    if (!data) return;

    data.nodeData = node;

    // Update position if provided
    if (node.position) {
      data.mesh.position.set(node.position.x, node.position.y, node.position.z);
    }
  }

  /**
   * Set the selected node (highlights selection ring).
   */
  setSelected(nodeId: string | null): void {
    // Clear all selections
    for (const data of this.nodeMeshes.values()) {
      (data.selRing.material as THREE.MeshBasicMaterial).opacity = 0;
    }

    // Highlight new selection
    if (nodeId) {
      const data = this.nodeMeshes.get(nodeId);
      if (data) {
        (data.selRing.material as THREE.MeshBasicMaterial).opacity = 0.4;
      }
    }
  }

  /**
   * Animate nodes each frame (rotation, pulsing, staleness fading).
   */
  animate(delta: number, elapsed: number): void {
    for (const data of this.nodeMeshes.values()) {
      // Slow rotation
      data.mesh.rotation.y += delta * 0.3;
      data.mesh.rotation.x += delta * 0.1;

      // Rings always face camera (billboarding handled by being children of mesh)
      data.ring.rotation.x = -data.mesh.rotation.x;
      data.ring.rotation.y = -data.mesh.rotation.y;

      // Target pulse effect
      if (data.nodeData.nodeType === "target") {
        const mat = data.mesh.material as THREE.MeshStandardMaterial;
        mat.emissiveIntensity = data.baseEmissive + Math.sin(elapsed * 2) * 0.15;
      }
    }
  }

  /**
   * Get all renderable node meshes (for raycasting).
   */
  getMeshes(): THREE.Object3D[] {
    return Array.from(this.nodeMeshes.values()).map((d) => d.mesh);
  }

  /**
   * Get node data by mesh reference.
   */
  getNodeByMesh(mesh: THREE.Object3D): NodeMeshData | undefined {
    const nodeId = mesh.userData?.nodeId;
    return nodeId ? this.nodeMeshes.get(nodeId) : undefined;
  }

  /**
   * Get mesh position for a given node ID.
   */
  getPosition(nodeId: string): THREE.Vector3 | null {
    const data = this.nodeMeshes.get(nodeId);
    return data ? data.mesh.position : null;
  }

  /**
   * Get the NodeMeshData by ID.
   */
  get(nodeId: string): NodeMeshData | undefined {
    return this.nodeMeshes.get(nodeId);
  }

  /**
   * Get all node IDs currently rendered.
   */
  getNodeIds(): string[] {
    return Array.from(this.nodeMeshes.keys());
  }

  // ── Private ──

  private computeInitialPosition(node: ClientNode): Vec3 {
    const index = this.nodeMeshes.size;
    const angle = index * 0.618033 * Math.PI * 2; // Golden angle

    let baseR: number;
    switch (node.nodeType) {
      case "target": baseR = 25; break;
      case "local":
      case "router":
      case "gateway": baseR = 40; break;
      default: baseR = 55; break;
    }

    const radius = baseR + Math.random() * 40;
    const yOff = node.nodeType === "target"
      ? (Math.random() - 0.5) * 15
      : (Math.random() - 0.5) * 40;

    return {
      x: Math.cos(angle) * radius + (Math.random() - 0.5) * 15,
      y: yOff,
      z: Math.sin(angle) * radius + (Math.random() - 0.5) * 15,
    };
  }
}
