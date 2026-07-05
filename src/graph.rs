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
}

pub fn load(manifest_path: Option<&Path>) -> Result<Vec<DependencyNode>> {
    let mut cmd = MetadataCommand::new();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = cmd.exec().context("failed to run `cargo metadata`")?;

    let resolve = metadata
        .resolve
        .as_ref()
        .context("no dependency resolution found — is this a valid Cargo project?")?;

    let workspace_ids: HashSet<&PackageId> = metadata.workspace_members.iter().collect();

    // Build forward edges (what each package pulls in) and reverse edges (who pulls each package in).
    // We only follow Normal dependency edges here. Dev and build deps don't ship with the crate,
    // so they shouldn't inflate depth or dependent counts for the packages beneath them.
    let mut children: HashMap<&PackageId, Vec<&PackageId>> = HashMap::new();
    let mut parents: HashMap<&PackageId, Vec<&PackageId>> = HashMap::new();

    for node in &resolve.nodes {
        let normal_deps: Vec<&PackageId> = node
            .deps
            .iter()
            .filter(|d| d.dep_kinds.iter().any(|k| k.kind == DependencyKind::Normal))
            .map(|d| &d.pkg)
            .collect();

        children.insert(&node.id, normal_deps.clone());

        for dep_id in normal_deps {
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
