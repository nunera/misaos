use crate::{Domain, Error, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// These helpers run only after the closed JSON Schema has checked the shapes.
fn text<'a>(object: &'a Value, key: &str) -> &'a str {
    object[key].as_str().expect("schema-checked string")
}
fn array<'a>(object: &'a Value, key: &str) -> &'a [Value] {
    object
        .get(key)
        .map(|v| v.as_array().expect("schema-checked array").as_slice())
        .unwrap_or(&[])
}
fn strings(items: &[Value]) -> impl Iterator<Item = &str> {
    items
        .iter()
        .map(|v| v.as_str().expect("schema-checked string array"))
}
fn set<'a>(items: impl Iterator<Item = &'a str>, field: &str) -> Result<()> {
    let mut previous = None;
    for item in items {
        if previous.is_some_and(|previous| previous >= item) {
            return Err(Error::schema(
                field,
                "set-like values must be strictly sorted with no duplicates",
            ));
        }
        previous = Some(item);
    }
    Ok(())
}
fn records(value: &Value, key: &str, id: &str) -> Result<()> {
    set(
        array(value, key).iter().map(|v| text(v, id)),
        &format!("/{key}"),
    )
}
fn features(value: &Value, field: &str) -> Result<()> {
    if !array(value, "requiredFeatures").is_empty() {
        return Err(Error::new(
            "E_CAPABILITY",
            field,
            "S0 qualifies no runtime features; the requested capability is unsupported",
        ));
    }
    Ok(())
}
fn decimal_u64(value: &Value, field: &str) -> Result<()> {
    if value
        .as_str()
        .expect("schema-checked decimal")
        .parse::<u64>()
        .is_err()
    {
        return Err(Error::schema(
            field,
            "decimal byte count exceeds unsigned 64-bit range",
        ));
    }
    Ok(())
}

pub(crate) fn validate(value: &Value, domain: Domain) -> Result<()> {
    features(value, "/requiredFeatures")?;
    if domain == Domain::Generation {
        set(strings(array(value, "roots")), "/roots")?;
        boot(&value["boot"], true)?;
        if value["adapterIdentity"] != value["boot"]["init"]["adapterBuildId"] {
            return Err(Error::schema(
                "/adapterIdentity",
                "adapter identity must match the boot adapter build",
            ));
        }
        return Ok(());
    }
    if value["foreignStorage"]["mode"] != "retain-all" {
        return Err(Error::new(
            "E_CAPABILITY",
            "/foreignStorage/mode",
            "leased-gc requires a separately qualified broker; this milestone supports retain-all only",
        ));
    }
    records(value, "roots", "name")?;
    records(value, "exports", "id")?;
    roots_and_exports(value, domain)?;
    trust(&value["trust"])?;
    if domain == Domain::Strata {
        records(value, "hostGrants", "id")?;
        grants(value)?;
    } else {
        host(value)?;
    }
    Ok(())
}

fn roots_and_exports(value: &Value, domain: Domain) -> Result<()> {
    let mut digests = BTreeSet::new();
    for (i, root) in array(value, "roots").iter().enumerate() {
        let digest = text(root, "digest");
        digests.insert(digest);
        if root["sealedPath"]["kind"] == "oci" && root["sealedPath"]["manifest"] != digest {
            return Err(Error::new(
                "E_LOCK",
                format!("/roots/{i}/sealedPath/manifest"),
                "OCI reference must locate the declared root manifest digest",
            ));
        }
        if domain == Domain::Plan {
            let expected = match text(&value["target"], "system") {
                "x86_64-linux" => "linux/amd64",
                "aarch64-linux" => "linux/arm64",
                _ => {
                    return Err(Error::new(
                        "E_CAPABILITY",
                        "/target/system",
                        "target is outside the S0 Linux schema profile",
                    ));
                }
            };
            if text(root, "platform") != expected {
                return Err(Error::new(
                    "E_ABI",
                    format!("/roots/{i}/platform"),
                    "foreign ISA differs from host; no emulator capability is qualified",
                ));
            }
        }
    }
    let grant_ids: BTreeSet<_> = array(value, "hostGrants")
        .iter()
        .map(|v| text(v, "id"))
        .collect();
    let mut names = BTreeSet::new();
    for (i, export) in array(value, "exports").iter().enumerate() {
        if !digests.contains(text(export, "root")) {
            return Err(Error::new(
                "E_LOCK",
                format!("/exports/{i}/root"),
                "export references no declared sealed root",
            ));
        }
        if !names.insert(text(export, "name")) {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/exports/{i}/name"),
                "export command name has multiple owners",
            ));
        }
        if let Some(desktop) = export.get("desktop") {
            set(
                array(desktop, "icons").iter().map(|v| text(v, "path")),
                &format!("/exports/{i}/desktop/icons"),
            )?;
            set(
                strings(array(desktop, "mime")),
                &format!("/exports/{i}/desktop/mime"),
            )?;
        }
        set(
            strings(array(export, "grants")),
            &format!("/exports/{i}/grants"),
        )?;
        for grant in strings(array(export, "grants")) {
            if !grant_ids.contains(grant) {
                return Err(Error::schema(
                    format!("/exports/{i}/grants"),
                    "export references an undeclared host grant",
                ));
            }
        }
    }
    Ok(())
}

fn overlaps(left: &str, right: &str) -> bool {
    left == right
        || left == "/"
        || right == "/"
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn reserved(path: &str) -> bool {
    [
        "/nix", "/boot", "/efi", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc",
        "/sys", "/dev", "/root",
    ]
    .iter()
    .any(|root| overlaps(path, root))
}

fn ownership(mut paths: Vec<(&str, String)>) -> Result<()> {
    paths.sort_unstable_by_key(|(path, _)| *path);
    let mut owners = BTreeMap::new();
    for (path, field) in paths {
        if owners.contains_key(path) || owners.contains_key("/") {
            return Err(Error::new(
                "E_PATH_OWNER",
                field,
                "managed path has another declarative owner",
            ));
        }
        for (slash, _) in path.match_indices('/').skip(1) {
            if owners.contains_key(&path[..slash]) {
                return Err(Error::new(
                    "E_PATH_OWNER",
                    field,
                    "managed paths overlap without an explicit ownership handoff",
                ));
            }
        }
        owners.insert(path, ());
    }
    Ok(())
}

fn grants(value: &Value) -> Result<()> {
    let mut targets = Vec::new();
    for (i, grant) in array(value, "hostGrants").iter().enumerate() {
        let source = text(grant, "source");
        let target = text(grant, "target");
        if source == "/" || reserved(target) || (grant["writable"] == true && reserved(source)) {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/hostGrants/{i}"),
                "grant would expose or replace host-system ownership",
            ));
        }
        targets.push((target, format!("/hostGrants/{i}/target")));
    }
    ownership(targets)
}

fn host(value: &Value) -> Result<()> {
    records(value, "providers", "id")?;
    records(value, "mounts", "target")?;
    records(value, "users", "name")?;
    records(value, "volumes", "volumeId")?;
    set(strings(array(&value["host"], "firmware")), "/host/firmware")?;
    let arch = match text(&value["target"], "system") {
        "x86_64-linux" => "x86_64",
        "aarch64-linux" => "aarch64",
        _ => {
            return Err(Error::new(
                "E_CAPABILITY",
                "/target/system",
                "unsupported target system",
            ));
        }
    };
    if value["target"]["kernelArch"] != arch {
        return Err(Error::new(
            "E_ABI",
            "/target/kernelArch",
            "kernel architecture does not match the target system",
        ));
    }
    if value["target"]["rootFs"] != value["boot"]["root"]["selector"] {
        return Err(Error::schema(
            "/target/rootFs",
            "target root selector differs from boot policy",
        ));
    }
    boot(&value["boot"], false)?;
    service_graph(&value["serviceGraph"])?;
    provider_graph(array(value, "providers"))?;
    let services: BTreeSet<_> = array(&value["serviceGraph"], "services")
        .iter()
        .map(|v| text(v, "id"))
        .collect();
    let providers: BTreeSet<_> = array(value, "providers")
        .iter()
        .map(|v| text(v, "id"))
        .collect();
    let provided: BTreeSet<_> = array(value, "providers")
        .iter()
        .flat_map(|p| strings(array(p, "provides")))
        .collect();
    for (i, provider) in array(value, "providers").iter().enumerate() {
        if !services.contains(text(provider, "id")) {
            return Err(Error::schema(
                format!("/providers/{i}/id"),
                "selected provider is not a service node",
            ));
        }
    }
    let mut paths = Vec::new();
    for (i, service) in array(&value["serviceGraph"], "services").iter().enumerate() {
        set(
            strings(array(service, "capabilities")),
            &format!("/serviceGraph/services/{i}/capabilities"),
        )?;
        for capability in strings(array(service, "capabilities")) {
            if !provided.contains(capability) {
                return Err(Error::new(
                    "E_CAPABILITY",
                    format!("/serviceGraph/services/{i}/capabilities"),
                    "service capability has no selected provider",
                ));
            }
        }
        for (field, id) in [("directories", "path"), ("sockets", "id")] {
            set(
                array(service, field).iter().map(|v| text(v, id)),
                &format!("/serviceGraph/services/{i}/{field}"),
            )?;
            for (j, item) in array(service, field).iter().enumerate() {
                let path = text(item, "path");
                if reserved(path) {
                    return Err(Error::new(
                        "E_PATH_OWNER",
                        format!("/serviceGraph/services/{i}/{field}/{j}/path"),
                        "service-owned paths cannot replace host system paths",
                    ));
                }
                paths.push((path, format!("/serviceGraph/services/{i}/{field}/{j}/path")));
            }
        }
    }
    for (i, mount) in array(value, "mounts").iter().enumerate() {
        let owner = text(mount, "owner");
        let target = text(mount, "target");
        if owner != text(value, "hostId") && !services.contains(owner) && !providers.contains(owner)
        {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/mounts/{i}/owner"),
                "mount owner is neither the host nor a declared service/provider",
            ));
        }
        if reserved(target) && owner != text(value, "hostId") {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/mounts/{i}/target"),
                "reserved system paths belong to the host",
            ));
        }
        paths.push((target, format!("/mounts/{i}/target")));
    }
    for (i, volume) in array(value, "volumes").iter().enumerate() {
        if !services.contains(text(volume, "owner")) {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/volumes/{i}/owner"),
                "volume owner is not a declared service",
            ));
        }
        let path = text(volume, "mountPath");
        if reserved(path) {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/volumes/{i}/mountPath"),
                "a mutable service volume cannot own host system paths",
            ));
        }
        set(
            strings(array(volume, "consumers")),
            &format!("/volumes/{i}/consumers"),
        )?;
        for consumer in strings(array(volume, "consumers")) {
            if !services.contains(consumer) {
                return Err(Error::schema(
                    format!("/volumes/{i}/consumers"),
                    "volume consumer is not a declared service",
                ));
            }
        }
        if let Some(migration) = volume.get("migration")
            && (volume["backupPolicy"]["kind"] == "none"
                || migration["toEpoch"].as_u64() <= volume["schemaEpoch"].as_u64())
        {
            return Err(Error::schema(
                format!("/volumes/{i}/migration"),
                "migration requires a snapshot policy and a newer schema epoch",
            ));
        }
        paths.push((path, format!("/volumes/{i}/mountPath")));
    }
    let mut uids = BTreeSet::new();
    for (i, user) in array(value, "users").iter().enumerate() {
        if !uids.insert(user["uid"].as_u64().expect("schema-checked uid")) {
            return Err(Error::schema(
                format!("/users/{i}/uid"),
                "UID belongs to more than one user",
            ));
        }
        let home = text(user, "home");
        if reserved(home) {
            return Err(Error::new(
                "E_PATH_OWNER",
                format!("/users/{i}/home"),
                "user home cannot own a host system path",
            ));
        }
        paths.push((home, format!("/users/{i}/home")));
    }
    ownership(paths)?;
    Ok(())
}

fn service_graph(graph: &Value) -> Result<()> {
    let nodes = array(graph, "services");
    set(
        nodes.iter().map(|v| text(v, "id")),
        "/serviceGraph/services",
    )?;
    let ids: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(i, v)| (text(v, "id"), i))
        .collect();
    let mut dependencies = vec![Vec::new(); nodes.len()];
    for (i, node) in nodes.iter().enumerate() {
        features(
            node,
            &format!("/serviceGraph/services/{i}/requiredFeatures"),
        )?;
        for key in ["requires", "wants", "after"] {
            set(
                strings(array(node, key)),
                &format!("/serviceGraph/services/{i}/{key}"),
            )?;
            for id in strings(array(node, key)) {
                let Some(&j) = ids.get(id) else {
                    return Err(Error::schema(
                        format!("/serviceGraph/services/{i}/{key}"),
                        "service edge references an undeclared node",
                    ));
                };
                if key == "requires" {
                    if node["scope"]["kind"] == "system" && nodes[j]["scope"]["kind"] == "user" {
                        return Err(Error::schema(
                            format!("/serviceGraph/services/{i}/requires"),
                            "system service cannot require a user service",
                        ));
                    }
                    if nodes[j]["kind"] == "milestone"
                        && array(&nodes[j], "requires").is_empty()
                        && array(&nodes[j], "wants").is_empty()
                        && graph["targets"]
                            .get(id)
                            .is_none_or(|v| v.as_array().expect("schema-checked target").is_empty())
                    {
                        return Err(Error::schema(
                            format!("/serviceGraph/services/{i}/requires"),
                            "required milestone has no members",
                        ));
                    }
                }
                if key != "wants" {
                    dependencies[i].push(j);
                }
            }
        }
    }
    for (name, members) in graph["targets"]
        .as_object()
        .expect("schema-checked targets")
    {
        let Some(&target) = ids.get(name.as_str()) else {
            return Err(Error::schema(
                format!("/serviceGraph/targets/{name}"),
                "target name is not a declared milestone",
            ));
        };
        if nodes[target]["kind"] != "milestone" {
            return Err(Error::schema(
                format!("/serviceGraph/targets/{name}"),
                "target name must identify a milestone",
            ));
        }
        set(
            strings(members.as_array().expect("schema-checked target members")),
            &format!("/serviceGraph/targets/{name}"),
        )?;
        for member in strings(members.as_array().expect("schema-checked target members")) {
            let Some(&member_index) = ids.get(member) else {
                return Err(Error::schema(
                    format!("/serviceGraph/targets/{name}"),
                    "target references an undeclared service",
                ));
            };
            if nodes[target]["scope"]["kind"] == "system"
                && nodes[member_index]["scope"]["kind"] == "user"
            {
                return Err(Error::schema(
                    format!("/serviceGraph/targets/{name}"),
                    "system milestone cannot require a user service",
                ));
            }
            dependencies[target].push(member_index);
        }
    }
    for prerequisites in &mut dependencies {
        prerequisites.sort_unstable();
        prerequisites.dedup();
    }
    acyclic(
        &dependencies,
        &nodes.iter().map(|n| text(n, "id")).collect::<Vec<_>>(),
        "/serviceGraph",
    )
}

fn provider_graph(nodes: &[Value]) -> Result<()> {
    let mut capabilities = BTreeMap::new();
    for (i, node) in nodes.iter().enumerate() {
        for key in ["provides", "requires"] {
            set(strings(array(node, key)), &format!("/providers/{i}/{key}"))?;
        }
        for capability in strings(array(node, "provides")) {
            if capabilities.insert(capability, i).is_some() {
                return Err(Error::new(
                    "E_CAPABILITY",
                    format!("/providers/{i}/provides"),
                    "capability has more than one selected provider",
                ));
            }
        }
    }
    let mut dependencies = vec![Vec::new(); nodes.len()];
    for (i, node) in nodes.iter().enumerate() {
        for capability in strings(array(node, "requires")) {
            let Some(&provider) = capabilities.get(capability) else {
                return Err(Error::new(
                    "E_CAPABILITY",
                    format!("/providers/{i}/requires"),
                    "required provider capability is absent",
                ));
            };
            dependencies[i].push(provider);
        }
        dependencies[i].sort_unstable();
        dependencies[i].dedup();
    }
    acyclic(
        &dependencies,
        &nodes.iter().map(|n| text(n, "id")).collect::<Vec<_>>(),
        "/providers",
    )
}

fn acyclic(dependencies: &[Vec<usize>], names: &[&str], field: &str) -> Result<()> {
    let mut remaining: Vec<_> = dependencies.iter().map(Vec::len).collect();
    let mut dependents = vec![Vec::new(); dependencies.len()];
    for (i, prerequisites) in dependencies.iter().enumerate() {
        for &j in prerequisites {
            dependents[j].push(i);
        }
    }
    let mut ready: VecDeque<_> = remaining
        .iter()
        .enumerate()
        .filter_map(|(i, n)| (*n == 0).then_some(i))
        .collect();
    while let Some(i) = ready.pop_front() {
        for &j in &dependents[i] {
            remaining[j] -= 1;
            if remaining[j] == 0 {
                ready.push_back(j);
            }
        }
    }
    if let Some(mut current) = remaining.iter().position(|n| *n > 0) {
        let mut positions = BTreeMap::new();
        let mut path = Vec::new();
        loop {
            if let Some(&start) = positions.get(&current) {
                path.push(names[current]);
                return Err(Error::schema(
                    field,
                    format!("dependency cycle: {}", path[start..].join(" -> ")),
                ));
            }
            positions.insert(current, path.len());
            path.push(names[current]);
            current = *dependencies[current]
                .iter()
                .find(|&&i| remaining[i] > 0)
                .expect("unresolved node has unresolved prerequisite");
        }
    }
    Ok(())
}

fn trust(value: &Value) -> Result<()> {
    let approvers = &value["approvers"];
    key_set(array(approvers, "keys"), "/trust/approvers/keys")?;
    if approvers["mode"] == "signed-by"
        && approvers["threshold"]
            .as_u64()
            .expect("schema-checked threshold")
            > array(approvers, "keys").len() as u64
    {
        return Err(Error::new(
            "E_TRUST",
            "/trust/approvers/threshold",
            "approval threshold exceeds the number of distinct keys",
        ));
    }
    set(
        array(value, "nixSubstituters")
            .iter()
            .map(|v| text(v, "url")),
        "/trust/nixSubstituters",
    )?;
    for (i, substituter) in array(value, "nixSubstituters").iter().enumerate() {
        key_set(
            array(substituter, "publicKeys"),
            &format!("/trust/nixSubstituters/{i}/publicKeys"),
        )?;
    }
    for (name, keys) in value["repoKeys"]
        .as_object()
        .expect("schema-checked repository map")
    {
        key_set(
            keys.as_array().expect("schema-checked keys"),
            &format!("/trust/repoKeys/{name}"),
        )?;
    }
    for (name, publishers) in value["imagePublishers"]
        .as_object()
        .expect("schema-checked publisher map")
    {
        let publishers = publishers.as_array().expect("schema-checked publishers");
        set(
            publishers.iter().map(|p| text(p, "keyId")),
            &format!("/trust/imagePublishers/{name}"),
        )?;
        for (i, publisher) in publishers.iter().enumerate() {
            if publisher["validFrom"].as_u64() >= publisher["validUntil"].as_u64() {
                return Err(Error::new(
                    "E_TRUST",
                    format!("/trust/imagePublishers/{name}/{i}/validUntil"),
                    "publisher validity interval must have positive duration",
                ));
            }
            if let Some(predecessor) = publisher.get("successorOf").and_then(Value::as_str)
                && (predecessor == text(publisher, "keyId")
                    || !publishers
                        .iter()
                        .any(|key| text(key, "keyId") == predecessor))
            {
                return Err(Error::new(
                    "E_TRUST",
                    format!("/trust/imagePublishers/{name}/{i}/successorOf"),
                    "successor must reference a distinct publisher key in this policy",
                ));
            }
        }
    }
    Ok(())
}

fn key_set(keys: &[Value], field: &str) -> Result<()> {
    set(keys.iter().map(|v| text(v, "keyId")), field)?;
    let mut material = BTreeSet::new();
    for key in keys {
        if !material.insert(text(key, "publicKey")) {
            return Err(Error::new(
                "E_TRUST",
                field,
                "one public key cannot count as multiple signers",
            ));
        }
    }
    Ok(())
}

fn boot(value: &Value, complete: bool) -> Result<()> {
    let root = &value["root"];
    let selector = &root["selector"];
    let expected = format!(
        "misa.root={}={}",
        text(selector, "kind"),
        text(selector, "value")
    );
    let tokens = array(&value["cmdline"], "template");
    if strings(tokens)
        .filter(|token| token.starts_with("misa.root="))
        .count()
        != 1
        || !strings(tokens).any(|token| token == expected)
    {
        return Err(Error::schema(
            "/boot/cmdline/template",
            "command line must contain exactly the declared persistent root selector",
        ));
    }
    if strings(tokens).any(|token| token.starts_with("misa.generation=")) {
        return Err(Error::schema(
            "/boot/cmdline/template",
            "generation ID is appended after hashing, never embedded in its own body",
        ));
    }
    set(strings(array(root, "mountFlags")), "/boot/root/mountFlags")?;
    if selector["kind"] == "luksuuid" {
        if value["unlock"]["method"] == "none" || value["unlock"]["luksUuid"] != selector["value"] {
            return Err(Error::schema(
                "/boot/unlock",
                "encrypted root selector requires a matching unlock policy",
            ));
        }
    } else if value["unlock"]["method"] != "none" {
        return Err(Error::schema(
            "/boot/unlock",
            "unlock policy requires a luksuuid root selector",
        ));
    }
    let health = &value["health"];
    set(strings(array(health, "gates")), "/boot/health/gates")?;
    set(
        strings(array(&health["bless"], "requires")),
        "/boot/health/bless/requires",
    )?;
    for gate in array(&health["bless"], "requires") {
        if !array(health, "gates").contains(gate) {
            return Err(Error::schema(
                "/boot/health/bless/requires",
                "blessing requires an undeclared health gate",
            ));
        }
    }
    if array(root, "mountFlags").iter().any(|flag| flag == "ro")
        && array(root, "mountFlags").iter().any(|flag| flag == "rw")
    {
        return Err(Error::schema(
            "/boot/root/mountFlags",
            "root cannot be both read-only and writable",
        ));
    }
    if let Some(uki) = value.get("uki") {
        let mut previous = None;
        for profile in array(uki, "profiles") {
            let id = profile["id"].as_u64().expect("schema-checked profile id");
            if previous.is_some_and(|previous| previous >= id) {
                return Err(Error::schema(
                    "/boot/uki/profiles",
                    "profile IDs must be strictly ordered and unique",
                ));
            }
            previous = Some(id);
            let profile_tokens = array(&profile["cmdline"], "template");
            if strings(profile_tokens)
                .filter(|t| t.starts_with("misa.root="))
                .count()
                != 1
                || !strings(profile_tokens).any(|t| t == expected)
                || strings(profile_tokens).any(|t| t.starts_with("misa.generation="))
            {
                return Err(Error::schema(
                    "/boot/uki/profiles",
                    "profile command line must bind the same root and exclude the derived generation ID",
                ));
            }
        }
        let signers = &uki["signerPolicy"];
        key_set(array(signers, "keys"), "/boot/uki/signerPolicy/keys")?;
        if signers["threshold"]
            .as_u64()
            .expect("schema-checked threshold")
            > array(signers, "keys").len() as u64
        {
            return Err(Error::new(
                "E_TRUST",
                "/boot/uki/signerPolicy/threshold",
                "signing threshold exceeds distinct keys",
            ));
        }
    }
    if !complete {
        return Ok(());
    }
    let arch = text(&value["platform"], "arch");
    let machine = value["init"]["elfMachine"]
        .as_u64()
        .expect("schema-checked ELF machine");
    if (arch == "x86_64" && machine != 62) || (arch == "aarch64" && machine != 183) {
        return Err(Error::new(
            "E_ABI",
            "/boot/init/elfMachine",
            "init ELF machine differs from boot architecture",
        ));
    }
    if value["kernel"]["uname"] != value["modules"]["uname"] {
        return Err(Error::schema(
            "/boot/modules/uname",
            "module release differs from kernel release",
        ));
    }
    decimal_u64(&value["kernel"]["size"], "/boot/kernel/size")?;
    let parts = array(&value["initrd"], "parts");
    if parts.iter().filter(|p| p["role"] == "main").count() != 1 {
        return Err(Error::schema(
            "/boot/initrd/parts",
            "initrd must contain exactly one main image",
        ));
    }
    for (i, part) in parts.iter().enumerate() {
        decimal_u64(&part["size"], &format!("/boot/initrd/parts/{i}/size"))?;
        if i != 0 && part["role"] == "microcode" {
            return Err(Error::schema(
                format!("/boot/initrd/parts/{i}/role"),
                "microcode, if present, must be the first initrd part",
            ));
        }
    }
    // Renderer appends a space plus misa.generation= and 64 hex digits (not sha256:).
    let rendered_length = strings(tokens).map(str::len).sum::<usize>()
        + tokens.len().saturating_sub(1)
        + 1
        + "misa.generation=".len()
        + 64;
    if rendered_length
        >= value["kernel"]["cmdlineLimit"]
            .as_u64()
            .expect("schema-checked limit") as usize
    {
        return Err(Error::schema(
            "/boot/cmdline/template",
            "rendered command line reaches the kernel byte limit",
        ));
    }
    set(
        strings(array(&value["firmware"], "initrdFiles")),
        "/boot/firmware/initrdFiles",
    )?;
    let mut mount_paths = Vec::new();
    for (i, mount) in array(value, "mounts").iter().enumerate() {
        set(
            strings(array(mount, "mountFlags")),
            &format!("/boot/mounts/{i}/mountFlags"),
        )?;
        mount_paths.push((text(mount, "target"), format!("/boot/mounts/{i}/target")));
    }
    ownership(mount_paths)?;
    Ok(())
}
