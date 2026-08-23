use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, MetadataCommand, PackageId};

#[derive(Debug)]
pub struct DependencyNode {
    pub name: String,
    pub version: semver::Version,
    /// True if this crate appears directly in a workspace member's [dependencies].
    pub is_direct: bool,
    /// Shortest path length from any workspace member to this node.
    pub depth: usize,
    /// Number of packages in the tree that directly depend on this one.
    pub dependent_count: usize,
    /// Number of DISTINCT packages that depend on this one directly OR
    /// transitively — the true "blast radius" if this crate broke.
    /// `dependent_count` alone understates impact for a crate whose direct
    /// dependents are themselves widely depended upon further up the tree.
    pub transitive_dependent_count: usize,
    /// True if this package is published on crates.io. Git and path
    /// dependencies never have crates.io metadata, so callers must not
    /// treat their absence as a fetch failure.
    pub is_registry: bool,
    /// How this crate is used. `Normal` if it ships with the built crate
    /// (via any path); otherwise the strongest reason it appears at all —
    /// see `NodeKind`'s ordering.
    pub kind: NodeKind,
}

/// Why a dependency appears in the graph. A single crate can be pulled in
/// multiple ways (e.g. a normal dep of one package and a dev-dep of
/// another); `Normal` always wins that classification since it's the
/// strictly broader risk (ships with the built crate, not just at
/// build/test time), then `Build` over `Dev` since a build script runs
/// arbitrary code on every build, not just during `cargo test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeKind {
    Dev,
    Build,
    Normal,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Normal => "normal",
            NodeKind::Build => "build",
            NodeKind::Dev => "dev",
        }
    }
}

/// Which non-`Normal` dependency kinds to additionally include. `Normal`
/// (runtime) dependencies are always followed regardless of these flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct KindOptions {
    pub include_build: bool,
    pub include_dev: bool,
}

/// Which cargo-standard consistency flags to pass through to the
/// underlying `cargo metadata` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    pub offline: bool,
    pub locked: bool,
    pub frozen: bool,
}

/// Returns the dependency nodes and the full resolved `cargo_metadata`
/// output — the caller needs more than just the nodes: the workspace root
/// (where `Cargo.lock` lives, for `--format sarif`'s `locations[]`) and the
/// package/workspace `[metadata]` tables (for `[package.metadata.depcheck]`
/// config, P2-5).
pub fn load(
    manifest_path: Option<&Path>,
    options: LoadOptions,
    kinds: KindOptions,
) -> Result<(Vec<DependencyNode>, cargo_metadata::Metadata)> {
    let mut cmd = MetadataCommand::new();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let mut extra = Vec::new();
    if options.frozen {
        extra.push("--frozen".to_string());
    } else {
        if options.offline {
            extra.push("--offline".to_string());
        }
        if options.locked {
            extra.push("--locked".to_string());
        }
    }
    if !extra.is_empty() {
        cmd.other_options(extra);
    }

    let metadata = cmd.exec().context("failed to run `cargo metadata`")?;
    let nodes = from_metadata(&metadata, kinds)?;
    Ok((nodes, metadata))
}

/// Pure transformation from a resolved `cargo metadata` graph to our own
/// `DependencyNode`s — split out from `load()` so it can be exercised
/// directly against fixture JSON in tests, with no `cargo metadata`
/// subprocess (and therefore no network) involved.
pub fn from_metadata(
    metadata: &cargo_metadata::Metadata,
    kinds: KindOptions,
) -> Result<Vec<DependencyNode>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .context("no dependency resolution found — is this a valid Cargo project?")?;

    let workspace_ids: HashSet<&PackageId> = metadata.workspace_members.iter().collect();

    // Build forward edges (what each package pulls in) and reverse edges
    // (who pulls each package in). Normal edges are always followed; Build
    // and Dev edges are followed only when explicitly requested, since
    // neither ships with the built crate. `kind_map` records, for every
    // package that ends up in the graph, the strongest reason it's there
    // (see `NodeKind`'s ordering) — independent of which edge a BFS
    // happens to discover it through first.
    let mut children: HashMap<&PackageId, Vec<&PackageId>> = HashMap::new();
    let mut parents: HashMap<&PackageId, Vec<&PackageId>> = HashMap::new();
    let mut kind_map: HashMap<&PackageId, NodeKind> = HashMap::new();

    for node in &resolve.nodes {
        let mut included: Vec<&PackageId> = Vec::new();

        for dep in &node.deps {
            let dep_kind = if dep
                .dep_kinds
                .iter()
                .any(|k| k.kind == DependencyKind::Normal)
            {
                Some(NodeKind::Normal)
            } else if kinds.include_build
                && dep
                    .dep_kinds
                    .iter()
                    .any(|k| k.kind == DependencyKind::Build)
            {
                Some(NodeKind::Build)
            } else if kinds.include_dev
                && dep
                    .dep_kinds
                    .iter()
                    .any(|k| k.kind == DependencyKind::Development)
            {
                Some(NodeKind::Dev)
            } else {
                None
            };

            let Some(dep_kind) = dep_kind else { continue };

            included.push(&dep.pkg);
            let entry = kind_map.entry(&dep.pkg).or_insert(dep_kind);
            if dep_kind > *entry {
                *entry = dep_kind;
            }
        }

        children.insert(&node.id, included.clone());

        for dep_id in included {
            parents.entry(dep_id).or_default().push(&node.id);
        }
    }

    // BFS from all workspace roots to assign the minimum depth to every reachable package.
    // Workspace members themselves are depth 0; their immediate deps are depth 1, and so on.
    let mut depth_map: HashMap<&PackageId, usize> = HashMap::new();
    let mut queue: VecDeque<(&PackageId, usize)> = VecDeque::new();

    for id in &workspace_ids {
        depth_map.insert(id, 0);
        queue.push_back((id, 0));
    }

    while let Some((id, depth)) = queue.pop_front() {
        for dep_id in children.get(id).into_iter().flatten() {
            let slot = depth_map.entry(dep_id).or_insert(usize::MAX);
            if depth + 1 < *slot {
                *slot = depth + 1;
                queue.push_back((dep_id, depth + 1));
            }
        }
    }

    // Direct deps are the immediate Normal-dep children of workspace members (depth == 1).
    let direct_ids: HashSet<&PackageId> = workspace_ids
        .iter()
        .flat_map(|id| children.get(id).into_iter().flatten().copied())
        .collect();

    // Transitive reverse-dependency closure: for each package, every other
    // package reachable by walking `parents` upward. This is an O(V*(V+E))
    // pass, which is fine at the scale a dependency graph actually reaches
    // (hundreds, occasionally low thousands, of nodes).
    let mut transitive_dependents: HashMap<&PackageId, usize> = HashMap::new();
    for id in resolve.nodes.iter().map(|n| &n.id) {
        let mut seen: HashSet<&PackageId> = HashSet::new();
        let mut queue: VecDeque<&PackageId> =
            parents.get(id).into_iter().flatten().copied().collect();
        while let Some(p) = queue.pop_front() {
            if seen.insert(p) {
                queue.extend(parents.get(p).into_iter().flatten().copied());
            }
        }
        transitive_dependents.insert(id, seen.len());
    }

    let package_map: HashMap<&PackageId, &cargo_metadata::Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    let mut nodes: Vec<DependencyNode> = resolve
        .nodes
        .iter()
        .filter(|n| !workspace_ids.contains(&n.id))
        .filter_map(|n| {
            let pkg = package_map.get(&n.id)?;
            let depth = *depth_map.get(&n.id).unwrap_or(&usize::MAX);

            Some(DependencyNode {
                name: pkg.name.to_string(),
                version: pkg.version.clone(),
                is_direct: direct_ids.contains(&n.id),
                depth,
                dependent_count: parents.get(&n.id).map_or(0, |v| v.len()),
                transitive_dependent_count: transitive_dependents.get(&n.id).copied().unwrap_or(0),
                is_registry: pkg.source.as_ref().is_some_and(|s| s.is_crates_io()),
                kind: kind_map.get(&n.id).copied().unwrap_or(NodeKind::Normal),
            })
        })
        .collect();

    // Drop crates with no reachable depth — these are build-script-only deps (autocfg, cc, etc.)
    // that don't appear in the normal runtime dependency graph and aren't relevant to health scoring.
    nodes.retain(|n| n.depth != usize::MAX);

    // Sort by depth first (most foundational crates first), then alphabetically within each depth.
    nodes.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));

    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loads a fixture workspace under `tests/fixtures/` via a real (but
    /// network-free — every dependency is a local path) `cargo metadata`
    /// invocation, so these tests exercise the exact same parsing path as
    /// production, not a hand-serialized stand-in that could drift from the
    /// real schema.
    fn load_fixture(name: &str) -> cargo_metadata::Metadata {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("Cargo.toml");
        cargo_metadata::MetadataCommand::new()
            .manifest_path(&manifest)
            .exec()
            .unwrap_or_else(|e| panic!("fixture {name} failed to resolve: {e}"))
    }

    fn find<'a>(nodes: &'a [DependencyNode], name: &str) -> &'a DependencyNode {
        nodes
            .iter()
            .find(|n| n.name == name)
            .unwrap_or_else(|| panic!("{name} missing from graph output: {nodes:?}"))
    }

    #[test]
    fn bfs_assigns_increasing_depth_along_a_chain() {
        let metadata = load_fixture("chain");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        // The workspace member itself (chain-root) is depth 0 and is never
        // emitted — only its dependencies are.
        assert!(nodes.iter().all(|n| n.name != "chain-root"));

        let mid = find(&nodes, "chain-mid");
        let leaf = find(&nodes, "chain-leaf");
        assert_eq!(mid.depth, 1);
        assert_eq!(leaf.depth, 2);
    }

    #[test]
    fn transitive_dependent_count_includes_the_whole_upward_chain() {
        // chain-leaf's only direct parent is chain-mid, but chain-mid is
        // itself depended on by the workspace root — so breaking chain-leaf
        // has a larger blast radius (2: mid + root) than its direct count
        // (1) suggests. This is exactly the gap dependent_count alone
        // can't see, and why the graph multiplier now uses this instead.
        let metadata = load_fixture("chain");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        let mid = find(&nodes, "chain-mid");
        let leaf = find(&nodes, "chain-leaf");
        assert_eq!(mid.dependent_count, 1);
        assert_eq!(mid.transitive_dependent_count, 1);
        assert_eq!(leaf.dependent_count, 1);
        assert_eq!(
            leaf.transitive_dependent_count, 2,
            "leaf's blast radius must include both mid and the root that depends on mid"
        );
    }

    #[test]
    fn transitive_dependent_count_is_never_less_than_direct() {
        for fixture in ["chain", "dep-kinds", "multi-member"] {
            let metadata = load_fixture(fixture);
            let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();
            for n in &nodes {
                assert!(
                    n.transitive_dependent_count >= n.dependent_count,
                    "{} in {fixture}: transitive {} < direct {}",
                    n.name,
                    n.transitive_dependent_count,
                    n.dependent_count
                );
            }
        }
    }

    #[test]
    fn direct_vs_transitive_matches_depth_one() {
        let metadata = load_fixture("chain");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        let mid = find(&nodes, "chain-mid");
        let leaf = find(&nodes, "chain-leaf");
        assert!(mid.is_direct, "depth-1 dependency must be direct");
        assert!(!leaf.is_direct, "depth-2 dependency must not be direct");
    }

    #[test]
    fn dependent_count_reflects_direct_parents_in_the_resolved_graph() {
        let metadata = load_fixture("chain");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        // chain-leaf has exactly one parent in the graph: chain-mid.
        let leaf = find(&nodes, "chain-leaf");
        assert_eq!(leaf.dependent_count, 1);
    }

    #[test]
    fn dev_and_build_only_dependencies_are_excluded() {
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        assert!(
            nodes.iter().any(|n| n.name == "normal-dep"),
            "a normal dependency must be present"
        );
        assert!(
            nodes.iter().all(|n| n.name != "dev-only-dep"),
            "a dev-only dependency must not appear in the graph: {nodes:?}"
        );
        assert!(
            nodes.iter().all(|n| n.name != "build-only-dep"),
            "a build-only dependency must not appear in the graph: {nodes:?}"
        );
    }

    #[test]
    fn normal_dep_is_always_classified_normal() {
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();
        assert_eq!(find(&nodes, "normal-dep").kind, NodeKind::Normal);
    }

    #[test]
    fn include_build_surfaces_build_only_dep_classified_as_build() {
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(
            &metadata,
            KindOptions {
                include_build: true,
                include_dev: false,
            },
        )
        .unwrap();

        assert_eq!(find(&nodes, "build-only-dep").kind, NodeKind::Build);
        assert!(
            nodes.iter().all(|n| n.name != "dev-only-dep"),
            "--include-build alone must not pull in dev-only deps: {nodes:?}"
        );
    }

    #[test]
    fn include_dev_surfaces_dev_only_dep_classified_as_dev() {
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(
            &metadata,
            KindOptions {
                include_build: false,
                include_dev: true,
            },
        )
        .unwrap();

        assert_eq!(find(&nodes, "dev-only-dep").kind, NodeKind::Dev);
        assert!(
            nodes.iter().all(|n| n.name != "build-only-dep"),
            "--include-dev alone must not pull in build-only deps: {nodes:?}"
        );
    }

    #[test]
    fn include_build_and_dev_surface_both_with_correct_kinds() {
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(
            &metadata,
            KindOptions {
                include_build: true,
                include_dev: true,
            },
        )
        .unwrap();

        assert_eq!(find(&nodes, "normal-dep").kind, NodeKind::Normal);
        assert_eq!(find(&nodes, "build-only-dep").kind, NodeKind::Build);
        assert_eq!(find(&nodes, "dev-only-dep").kind, NodeKind::Dev);
    }

    #[test]
    fn unreachable_packages_are_dropped_not_left_at_max_depth() {
        // dev-only-dep and build-only-dep both resolve to depth == usize::MAX
        // internally (never reached by the Normal-edges-only BFS) and must be
        // filtered out of the final output entirely, not emitted with a
        // nonsensical depth.
        let metadata = load_fixture("dep-kinds");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();
        assert!(nodes.iter().all(|n| n.depth != usize::MAX));
    }

    #[test]
    fn bfs_starts_from_every_workspace_member_not_just_one() {
        // Two workspace members (member-a, member-b) both depend on the
        // same path crate (mm-shared). BFS must seed from every workspace
        // root, not just the first one — otherwise mm-shared's depth or
        // dependent_count would silently miss the edge from whichever
        // member isn't treated as a root.
        let metadata = load_fixture("multi-member");
        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();

        assert!(nodes
            .iter()
            .all(|n| n.name != "member-a" && n.name != "member-b"));

        let shared = find(&nodes, "mm-shared");
        assert_eq!(shared.depth, 1, "reachable at depth 1 from either member");
        assert_eq!(
            shared.dependent_count, 2,
            "both member-a and member-b depend on it directly"
        );
        assert!(shared.is_direct);
    }

    #[test]
    fn duplicate_resolved_versions_of_the_same_crate_both_survive() {
        // graph.rs keys everything by PackageId, never by name, so two
        // versions of the same crate name must both appear as independent
        // nodes rather than one clobbering the other. Constructed by cloning
        // a real resolved graph and duplicating one package's entry at a
        // different version under a synthetic id, since a genuine
        // same-name-two-versions graph normally only arises via the crates.io
        // registry, which these fixtures deliberately avoid.
        let mut metadata = load_fixture("chain");
        let resolve = metadata.resolve.as_mut().unwrap();

        let leaf_pkg = metadata
            .packages
            .iter()
            .find(|p| p.name.as_str() == "chain-leaf")
            .unwrap()
            .clone();
        let leaf_node = resolve
            .nodes
            .iter()
            .find(|n| n.id == leaf_pkg.id)
            .unwrap()
            .clone();

        let mut dup_pkg = leaf_pkg.clone();
        let dup_id = cargo_metadata::PackageId {
            repr: format!("{}+duplicate", leaf_pkg.id.repr),
        };
        dup_pkg.id = dup_id.clone();
        dup_pkg.version = semver::Version::new(9, 9, 9);

        let mut dup_node = leaf_node.clone();
        dup_node.id = dup_id.clone();

        // Wire chain-root -> the duplicate too, so it's reachable at depth 1
        // (distinct from the original chain-leaf's depth 2), proving depth
        // and dependent_count are tracked per-PackageId, not merged by name.
        let root_id = metadata.workspace_members[0].clone();
        let root_node = resolve.nodes.iter_mut().find(|n| n.id == root_id).unwrap();
        let mut dup_dep = root_node
            .deps
            .iter()
            .find(|d| d.pkg == leaf_pkg.id)
            .cloned()
            .unwrap_or_else(|| root_node.deps[0].clone());
        dup_dep.pkg = dup_id.clone();
        root_node.deps.push(dup_dep);
        root_node.dependencies.push(dup_id);

        metadata.packages.push(dup_pkg);
        resolve.nodes.push(dup_node);

        let nodes = from_metadata(&metadata, KindOptions::default()).unwrap();
        let leaf_nodes: Vec<&DependencyNode> =
            nodes.iter().filter(|n| n.name == "chain-leaf").collect();

        assert_eq!(
            leaf_nodes.len(),
            2,
            "both versions must survive as independent nodes: {nodes:?}"
        );
        assert!(leaf_nodes
            .iter()
            .any(|n| n.version == semver::Version::new(9, 9, 9)));
        assert!(leaf_nodes
            .iter()
            .any(|n| n.version != semver::Version::new(9, 9, 9)));
    }
}
