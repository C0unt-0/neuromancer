// ═══════════════════════════════════════════════════
//  CYBERDECK — Scene Manager
//  Core Three.js setup: renderer, camera, controls,
//  postprocessing, and render loop
// ═══════════════════════════════════════════════════

import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";
import { createGrid } from "./grid.js";

export class SceneManager {
  public scene: THREE.Scene;
  public camera: THREE.PerspectiveCamera;
  public renderer: THREE.WebGLRenderer;
  public controls: OrbitControls;
  public composer: EffectComposer;
  public raycaster: THREE.Raycaster;
  public mouse: THREE.Vector2;

  private canvas: HTMLCanvasElement;
  private viewport: HTMLElement;
  private animationCallbacks: Array<(delta: number, elapsed: number) => void> = [];
  private clock: THREE.Clock;
  private running = false;

  constructor(canvas: HTMLCanvasElement, viewport: HTMLElement) {
    this.canvas = canvas;
    this.viewport = viewport;
    this.clock = new THREE.Clock();

    // ── Renderer ──
    this.renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.toneMapping = THREE.ReinhardToneMapping;
    this.renderer.toneMappingExposure = 1.5;

    // ── Scene ──
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x0a0a0f, 0.0012);

    // ── Camera ──
    this.camera = new THREE.PerspectiveCamera(60, 1, 0.1, 2000);
    this.camera.position.set(0, 80, 160);

    // ── Controls ──
    this.controls = new OrbitControls(this.camera, canvas);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.05;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 0.2;
    this.controls.maxDistance = 500;
    this.controls.minDistance = 15;

    // ── Lights ──
    this.scene.add(new THREE.AmbientLight(0x404060, 0.5));
    const dirLight = new THREE.DirectionalLight(0x00f0ff, 0.3);
    dirLight.position.set(50, 100, 50);
    this.scene.add(dirLight);

    // ── Grid ──
    createGrid(this.scene);

    // ── Postprocessing ──
    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));

    const bloom = new UnrealBloomPass(
      new THREE.Vector2(1, 1),
      1.0,  // strength
      0.4,  // radius
      0.15, // threshold
    );
    this.composer.addPass(bloom);
    this.composer.addPass(new OutputPass());

    // ── Raycaster ──
    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2();

    // ── Resize handling ──
    this.handleResize();
    window.addEventListener("resize", () => this.handleResize());
  }

  /**
   * Register a callback to run every frame.
   */
  onAnimate(callback: (delta: number, elapsed: number) => void): void {
    this.animationCallbacks.push(callback);
  }

  /**
   * Start the render loop.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.clock.start();
    this.animate();
  }

  /**
   * Stop the render loop.
   */
  stop(): void {
    this.running = false;
  }

  /**
   * Get the intersected mesh from a mouse/pointer event.
   */
  getIntersectedMesh(
    event: MouseEvent,
    meshes: THREE.Object3D[],
  ): THREE.Object3D | null {
    const rect = this.canvas.getBoundingClientRect();
    this.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    this.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    this.raycaster.setFromCamera(this.mouse, this.camera);

    const hits = this.raycaster.intersectObjects(meshes, false);
    return hits.length > 0 ? hits[0].object : null;
  }

  /**
   * Update zoom indicator HUD element.
   */
  updateZoomIndicator(): void {
    const dist = this.camera.position.distanceTo(this.controls.target);
    const zoom = (160 / dist).toFixed(1);
    const el = document.getElementById("zoom-ind");
    if (el) el.textContent = `ZOOM ${zoom}x`;
  }

  // ── Private ──

  private animate = (): void => {
    if (!this.running) return;
    requestAnimationFrame(this.animate);

    const delta = this.clock.getDelta();
    const elapsed = this.clock.getElapsedTime();

    // Update controls
    this.controls.update();

    // Run registered callbacks
    for (const cb of this.animationCallbacks) {
      cb(delta, elapsed);
    }

    // Update zoom HUD
    this.updateZoomIndicator();

    // Render via postprocessing pipeline
    this.composer.render();
  };

  private handleResize(): void {
    const rect = this.viewport.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;

    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
    this.composer.setSize(w, h);
  }
}
