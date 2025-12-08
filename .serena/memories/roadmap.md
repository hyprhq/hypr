# Roadmap & Active Tasks

## Current Goal: Phase 3.5 - Multi-Stage Builds & Compose Integration

### CRITICAL GAPS (Immediate Priority)

1. **Multi-Stage Dockerfile Support (BLOCKING)**
   - Parser: WORKS (extracts `from_stage` field correctly)
   - Graph: WORKS (tracks stage dependencies, validates stage refs)
   - Execution: BROKEN - VM executors ignore `from_stage` field
   - Location: `hypr-core/src/builder/executor.rs`
   - Fix: Track stage rootfs outputs, copy from stage instead of /context

2. **Compose `build:` Directive**
   - Current: Only `image:` supported
   - Needed: Support `build: ./path` and `build: { context: ..., dockerfile: ... }`
   - Integration: Must work with multi-stage builds

### Implementation Plan

**Phase 3.5a: Multi-Stage Builds**
1. Add `stage_outputs: HashMap<String, PathBuf>` to track each stage's rootfs
2. After building each stage, store its rootfs path with stage name
3. Modify COPY instruction handling to check `from_stage`:
   - If `from_stage` is Some: copy from that stage's rootfs
   - If `from_stage` is None: copy from /context (current behavior)
4. Update kestrel.c to support COPY_FROM_STAGE command type
5. Remove "Multi-stage builds not yet supported" error

**Phase 3.5b: Compose Build Integration**
1. Extend compose types to parse `build:` directive
2. Add BuildSpec variant to Service type
3. In converter: if build spec present, trigger image build before VM creation
4. Support `depends_on` + build ordering

### Previous Phases (Completed)

- Phase 1: Core VM infrastructure ✓
- Phase 2: Networking infrastructure ✓
- Phase 2.5: Network wiring ✓
- Phase 3: Build system (single-stage) ✓

### Future Phases

- Phase 4: GPU Support (VFIO/Metal passthrough)
- Phase 5: Production readiness (health checks, metrics)
- Phase 6: Multi-node orchestration