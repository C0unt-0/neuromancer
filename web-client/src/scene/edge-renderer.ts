// ═══════════════════════════════════════════════════
//  CYBERDECK — Edge Renderer
//  Draws connections between nodes with protocol-colored
//  lines at low opacity
// ═══════════════════════════════════════════════════

import * as THREE from "three";
import type { ClientEdge } from "../types.js";
import { PROTOCOL_COLORS } from "../config.js";
import type { NodeRenderer } from "./node-renderer.js";

export interface EdgeMeshData {
  line: THREE.Line;
  edgeData: ClientEdge;
}

export class EdgeRenderer {
  private scene: THREE.Scene;
  private nodeRenderer: NodeRenderer;
  private edgeMeshes: Map<string, EdgeMeshData> = new Map();

  constructor(scene: THREE.Scene, nodeRenderer: NodeRenderer) {
    this.scene = scene;
    this.nodeRenderer = nodeRenderer;
  }

  /**
   * Add an edge between two nodes.
   */
  addEdge(edge: ClientEdge): void {
    if (this.edgeMeshes.has(edge.id)) return;

    const srcPos = this.nodeRenderer.getPosition(edge.sourceIp);
    const dstPos = this.nodeRenderer.getPosition(edge.targetIp);
    if (!srcPos || !dstPos) return;

    const colorHex = PROTOCOL_COLORS[edge.protocol] ?? "#ffffff";
    const color = new THREE.Color(colorHex);

    const geometry = new THREE.BufferGeometry().setFromPoints([
      srcPos.clone(),
      dstPos.clone(),
    ]);

    const material = new THREE.LineBasicMaterial({
      color,
      transparent: true,
      opacity: 0.1,
    });

    const line = new THREE.Line(geometry, material);
    line.userData = { edgeId: edge.id };

    this.scene.add(line);
    this.edgeMeshes.set(edge.id, { line, edgeData: edge });
  }

  /**
   * Remove an edge from the scene.
   */
  removeEdge(edgeId: string): void {
    const data = this.edgeMeshes.get(edgeId);
    if (data) {
      this.scene.remove(data.line);
      data.line.geometry.dispose();
      (data.line.material as THREE.Material).dispose();
      this.edgeMeshes.delete(edgeId);
    }
  }

  /**
   * Update edge positions (call when nodes move).
   */
  updatePositions(): void {
    for (const data of this.edgeMeshes.values()) {
      const srcPos = this.nodeRenderer.getPosition(data.edgeData.sourceIp);
      const dstPos = this.nodeRenderer.getPosition(data.edgeData.targetIp);
      if (!srcPos || !dstPos) continue;

      const positions = data.line.geometry.attributes.position;
      if (positions) {
        (positions as THREE.BufferAttribute).setXYZ(0, srcPos.x, srcPos.y, srcPos.z);
        (positions as THREE.BufferAttribute).setXYZ(1, dstPos.x, dstPos.y, dstPos.z);
        positions.needsUpdate = true;
      }
    }
  }

  /**
   * Get edge data for a given edge ID.
   */
  get(edgeId: string): EdgeMeshData | undefined {
    return this.edgeMeshes.get(edgeId);
  }

  /**
   * Get all edge IDs currently rendered.
   */
  getEdgeIds(): string[] {
    return Array.from(this.edgeMeshes.keys());
  }
}
