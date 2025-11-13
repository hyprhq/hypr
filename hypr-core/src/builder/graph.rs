//! Build graph (DAG) for HYPR image building.
//!
//! Converts a parsed Dockerfile into a directed acyclic graph of build steps,
//! with cache key computation and topological sorting for execution.

use crate::builder::parser::{Dockerfile, Instruction};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

/// A directed acyclic graph representing a build plan.
#[derive(Debug, Clone)]
pub struct BuildGraph {
    /// All nodes in the graph
    pub nodes: Vec<BuildNode>,
    /// Adjacency list: node_id -> [dependent_node_ids]
    pub edges: HashMap<usize, Vec<usize>>,
    /// Root nodes (no dependencies)
    pub roots: Vec<usize>,
}

/// A single node in the build graph (one build step).
#[derive(Debug, Clone)]
pub struct BuildNode {
    /// Unique node ID
    pub id: usize,
    /// The instruction to execute
    pub instruction: Instruction,
    /// Stage index (for multi-stage builds)
    pub stage_index: usize,
    /// Cache key (sha256 hash of step content + parent hash)
    pub cache_key: String,
    /// Parent node ID (for sequential dependencies)
    pub parent: Option<usize>,
    /// Build context files this step depends on (for COPY/ADD)
    pub context_dependencies: Vec<String>,
}

/// Error type for build graph operations.
#[derive(Debug, Clone)]
pub enum GraphError {
    /// Circular dependency detected
    CircularDependency { cycle: Vec<usize> },
    /// Unknown stage reference
    UnknownStage { stage_name: String },
    /// Invalid graph state
    InvalidGraph { message: String },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GraphError::CircularDependency { cycle } => {
                write!(f, "Circular dependency detected: {:?}", cycle)
            }
            GraphError::UnknownStage { stage_name } => {
                write!(f, "Unknown stage reference: {}", stage_name)
            }
            GraphError::InvalidGraph { message } => {
                write!(f, "Invalid graph: {}", message)
            }
        }
    }
}

impl std::error::Error for GraphError {}

impl BuildGraph {
    /// Creates a build graph from a parsed Dockerfile.
    ///
    /// # Arguments
    /// * `dockerfile` - The parsed Dockerfile
    ///
    /// # Returns
    /// * `Ok(BuildGraph)` - Successfully constructed build graph
    /// * `Err(GraphError)` - Error constructing graph (e.g., circular dependency)
    pub fn from_dockerfile(dockerfile: &Dockerfile) -> Result<Self, GraphError> {
        let builder = GraphBuilder::new(dockerfile);
        builder.build()
    }

    /// Returns nodes in topological order (execution order).
    ///
    /// # Returns
    /// * `Ok(Vec<usize>)` - Node IDs in execution order
    /// * `Err(GraphError)` - Circular dependency detected
    pub fn topological_sort(&self) -> Result<Vec<usize>, GraphError> {
        // Kahn's algorithm for topological sorting
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue = VecDeque::new();

        // Calculate in-degree for all nodes
        for node in &self.nodes {
            in_degree.insert(node.id, 0);
        }

        for neighbors in self.edges.values() {
            for &neighbor in neighbors {
                *in_degree.get_mut(&neighbor).unwrap() += 1;
            }
        }

        // Add all nodes with in-degree 0 to queue
        for node in &self.nodes {
            if in_degree[&node.id] == 0 {
                queue.push_back(node.id);
            }
        }

        // Process nodes
        while let Some(node_id) = queue.pop_front() {
            result.push(node_id);

            // Reduce in-degree for neighbors
            if let Some(neighbors) = self.edges.get(&node_id) {
                for &neighbor in neighbors {
                    let degree = in_degree.get_mut(&neighbor).unwrap();
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        // Check if all nodes were processed
        if result.len() != self.nodes.len() {
            // Circular dependency detected
            let unprocessed: Vec<usize> =
                self.nodes.iter().map(|n| n.id).filter(|id| !result.contains(id)).collect();

            return Err(GraphError::CircularDependency { cycle: unprocessed });
        }

        Ok(result)
    }

    /// Gets a node by ID.
    pub fn get_node(&self, id: usize) -> Option<&BuildNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Gets dependencies for a node.
    pub fn get_dependencies(&self, node_id: usize) -> Vec<usize> {
        // Find all nodes that point to this node
        let mut deps = Vec::new();
        for (from, to_list) in &self.edges {
            if to_list.contains(&node_id) {
                deps.push(*from);
            }
        }
        deps
    }
}

/// Internal builder for constructing the build graph.
struct GraphBuilder<'a> {
    dockerfile: &'a Dockerfile,
    nodes: Vec<BuildNode>,
    edges: HashMap<usize, Vec<usize>>,
    next_node_id: usize,
    /// Map of stage name -> last node ID in that stage
    stage_outputs: HashMap<String, usize>,
}

impl<'a> GraphBuilder<'a> {
    fn new(dockerfile: &'a Dockerfile) -> Self {
        Self {
            dockerfile,
            nodes: Vec::new(),
            edges: HashMap::new(),
            next_node_id: 0,
            stage_outputs: HashMap::new(),
        }
    }

    fn build(mut self) -> Result<BuildGraph, GraphError> {
        // Process each stage
        for (stage_idx, stage) in self.dockerfile.stages.iter().enumerate() {
            self.process_stage(stage_idx, stage)?;
        }

        // Find root nodes (those with no incoming edges)
        let mut all_targets: HashSet<usize> = HashSet::new();
        for targets in self.edges.values() {
            all_targets.extend(targets);
        }

        let roots: Vec<usize> =
            self.nodes.iter().filter(|n| !all_targets.contains(&n.id)).map(|n| n.id).collect();

        Ok(BuildGraph { nodes: self.nodes, edges: self.edges, roots })
    }

    fn process_stage(
        &mut self,
        stage_idx: usize,
        stage: &crate::builder::parser::BuildStage,
    ) -> Result<(), GraphError> {
        let mut parent_node_id: Option<usize> = None;

        // Process each instruction in the stage
        for instruction in &stage.instructions {
            let node_id = self.create_node(stage_idx, instruction.clone(), parent_node_id)?;

            // Add edge from parent to this node (sequential dependency)
            if let Some(parent_id) = parent_node_id {
                self.add_edge(parent_id, node_id);
            }

            parent_node_id = Some(node_id);
        }

        // Record the final node of this stage
        if let Some(stage_name) = &stage.name {
            if let Some(final_node) = parent_node_id {
                self.stage_outputs.insert(stage_name.clone(), final_node);
            }
        }

        Ok(())
    }

    fn create_node(
        &mut self,
        stage_index: usize,
        instruction: Instruction,
        parent: Option<usize>,
    ) -> Result<usize, GraphError> {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        // Compute cache key
        let cache_key = self.compute_cache_key(&instruction, parent)?;

        // Extract context dependencies (for COPY/ADD)
        let context_dependencies = self.extract_context_dependencies(&instruction);

        // Handle COPY --from=stage
        if let Instruction::Copy { from_stage: Some(ref from_stage_name), .. } = instruction {
            // Add dependency on the source stage's final node
            if let Some(&source_node_id) = self.stage_outputs.get(from_stage_name) {
                self.add_edge(source_node_id, node_id);
            } else {
                return Err(GraphError::UnknownStage { stage_name: from_stage_name.clone() });
            }
        }

        let node = BuildNode {
            id: node_id,
            instruction,
            stage_index,
            cache_key,
            parent,
            context_dependencies,
        };

        self.nodes.push(node);
        Ok(node_id)
    }

    fn compute_cache_key(
        &self,
        instruction: &Instruction,
        parent: Option<usize>,
    ) -> Result<String, GraphError> {
        let mut hasher = Sha256::new();

        // Hash the parent's cache key (for dependency chaining)
        if let Some(parent_id) = parent {
            if let Some(parent_node) = self.nodes.iter().find(|n| n.id == parent_id) {
                hasher.update(parent_node.cache_key.as_bytes());
            }
        }

        // Hash the instruction type and content
        let instruction_repr = format!("{:?}", instruction);
        hasher.update(instruction_repr.as_bytes());

        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    fn extract_context_dependencies(&self, instruction: &Instruction) -> Vec<String> {
        match instruction {
            Instruction::Copy { sources, from_stage: None, .. } => sources.clone(),
            Instruction::Add { sources, .. } => sources.clone(),
            _ => Vec::new(),
        }
    }

    fn add_edge(&mut self, from: usize, to: usize) {
        self.edges.entry(from).or_default().push(to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::parser::parse_dockerfile;

    #[test]
    fn test_simple_graph() {
        let dockerfile = r#"
FROM alpine:3.19
RUN apk add nginx
CMD ["nginx"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Should have 3 nodes (FROM, RUN, CMD)
        assert_eq!(graph.nodes.len(), 3);

        // Should be able to topologically sort
        let sorted = graph.topological_sort().unwrap();
        assert_eq!(sorted.len(), 3);

        // Nodes should be in order: FROM -> RUN -> CMD
        assert_eq!(sorted[0], 0); // FROM
        assert_eq!(sorted[1], 1); // RUN
        assert_eq!(sorted[2], 2); // CMD
    }

    #[test]
    fn test_multi_stage_graph() {
        let dockerfile = r#"
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

FROM alpine:3.19
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Stage 1: FROM, WORKDIR, COPY, RUN = 4 nodes
        // Stage 2: FROM, COPY --from, CMD = 3 nodes
        // Total: 7 nodes
        assert_eq!(graph.nodes.len(), 7);

        // Should have a dependency from builder's RUN to second stage's COPY
        let sorted = graph.topological_sort().unwrap();
        assert_eq!(sorted.len(), 7);

        // Find the COPY --from=builder node
        let copy_from_node = graph.nodes.iter().find(|n| {
            matches!(&n.instruction, Instruction::Copy { from_stage: Some(ref name), .. } if name == "builder")
        }).unwrap();

        // It should depend on the builder stage
        let deps = graph.get_dependencies(copy_from_node.id);
        assert!(!deps.is_empty(), "COPY --from should have dependencies");
    }

    #[test]
    fn test_cache_keys_unique() {
        let dockerfile = r#"
FROM alpine:3.19
RUN apk add nginx
RUN apk add curl
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // All nodes should have unique cache keys
        let mut keys = HashSet::new();
        for node in &graph.nodes {
            assert!(keys.insert(node.cache_key.clone()), "Duplicate cache key: {}", node.cache_key);
        }
    }

    #[test]
    fn test_cache_key_changes_with_content() {
        let dockerfile1 = r#"
FROM alpine:3.19
RUN apk add nginx
        "#;

        let dockerfile2 = r#"
FROM alpine:3.19
RUN apk add curl
        "#;

        let parsed1 = parse_dockerfile(dockerfile1).unwrap();
        let parsed2 = parse_dockerfile(dockerfile2).unwrap();

        let graph1 = BuildGraph::from_dockerfile(&parsed1).unwrap();
        let graph2 = BuildGraph::from_dockerfile(&parsed2).unwrap();

        // FROM nodes should have same cache key (same instruction)
        assert_eq!(graph1.nodes[0].cache_key, graph2.nodes[0].cache_key);

        // RUN nodes should have different cache keys (different commands)
        assert_ne!(graph1.nodes[1].cache_key, graph2.nodes[1].cache_key);
    }

    #[test]
    fn test_context_dependencies() {
        let dockerfile = r#"
FROM alpine:3.19
COPY file1.txt file2.txt /app/
ADD archive.tar.gz /data/
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Find COPY node
        let copy_node = graph
            .nodes
            .iter()
            .find(|n| matches!(&n.instruction, Instruction::Copy { .. }))
            .unwrap();

        assert_eq!(copy_node.context_dependencies.len(), 2);
        assert!(copy_node.context_dependencies.contains(&"file1.txt".to_string()));
        assert!(copy_node.context_dependencies.contains(&"file2.txt".to_string()));

        // Find ADD node
        let add_node =
            graph.nodes.iter().find(|n| matches!(&n.instruction, Instruction::Add { .. })).unwrap();

        assert_eq!(add_node.context_dependencies.len(), 1);
        assert!(add_node.context_dependencies.contains(&"archive.tar.gz".to_string()));
    }

    #[test]
    fn test_unknown_stage_reference() {
        let dockerfile = r#"
FROM alpine:3.19
COPY --from=nonexistent /app/file /dest/
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let result = BuildGraph::from_dockerfile(&parsed);

        assert!(result.is_err());
        if let Err(GraphError::UnknownStage { stage_name }) = result {
            assert_eq!(stage_name, "nonexistent");
        } else {
            panic!("Expected UnknownStage error");
        }
    }

    #[test]
    fn test_roots_identification() {
        let dockerfile = r#"
FROM golang:1.21 AS builder
RUN go build

FROM alpine:3.19
RUN apk add ca-certificates
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Should have 2 root nodes (the two FROM instructions)
        assert_eq!(graph.roots.len(), 2);

        // Both roots should be FROM instructions
        for &root_id in &graph.roots {
            let node = graph.get_node(root_id).unwrap();
            assert!(matches!(node.instruction, Instruction::From { .. }));
        }
    }

    #[test]
    fn test_parent_relationships() {
        let dockerfile = r#"
FROM alpine:3.19
RUN echo "step1"
RUN echo "step2"
RUN echo "step3"
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Check parent chain
        assert_eq!(graph.nodes[0].parent, None); // FROM has no parent
        assert_eq!(graph.nodes[1].parent, Some(0)); // RUN depends on FROM
        assert_eq!(graph.nodes[2].parent, Some(1)); // RUN depends on previous RUN
        assert_eq!(graph.nodes[3].parent, Some(2)); // RUN depends on previous RUN
    }

    #[test]
    fn test_topological_sort_deterministic() {
        let dockerfile = r#"
FROM alpine:3.19
RUN apk add nginx
COPY config.conf /etc/nginx/
CMD ["nginx"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        // Run toposort multiple times - should get same result
        let sort1 = graph.topological_sort().unwrap();
        let sort2 = graph.topological_sort().unwrap();
        let sort3 = graph.topological_sort().unwrap();

        assert_eq!(sort1, sort2);
        assert_eq!(sort2, sort3);
    }
}
