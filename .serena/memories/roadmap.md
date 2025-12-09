# Roadmap & Active Tasks

## Current Goal: Phase 3.5 - Multi-Stage Builds & Compose Integration

### Current Status

**Multi-Stage Dockerfile Support: WORKING** ✅
   - Parser: WORKS (extracts `from_stage` field correctly)
   - Graph: WORKS (tracks stage dependencies, validates stage refs)
   - Execution: WORKS - Both `LinuxVmBuilder` and `MacOsVmBuilder` properly handle:
     - `stage_outputs: HashMap<String, PathBuf>` tracking
     - `FROM <stage>` directive for stage-to-stage builds
     - `COPY --from=<stage>` for copying between stages via rsync
   - Location: `hypr-core/src/builder/executor.rs` (lines 1316-1621, 1911-2217)

**Remaining Work for Phase 3.5:**

1. **Compose `build:` Directive** (NOT YET IMPLEMENTED)
   - Current: Only `image:` supported
   - Needed: Support `build: ./path` and `build: { context: ..., dockerfile: ... }`
   - Integration: Must work with multi-stage builds

### Implementation Plan for Compose Build Integration

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