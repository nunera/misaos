//! Deterministic wire fixtures exercise the public verifier without extraction,
//! registries, privileges, external commands, or fabricated tool output.
use misa_image::model::{
    Descriptor, Limits, LockedImage, OCI_CONFIG, OCI_GZIP, OCI_INDEX, OCI_MANIFEST, OCI_TAR,
};
use misa_image::verify::verify_layout;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn wire(descriptor: &Descriptor) -> Value {
    json!({"mediaType": descriptor.media_type, "digest": descriptor.digest, "size": descriptor.size})
}

fn member(name: &str, kind: u8, data: &[u8], target: &str) -> Vec<u8> {
    assert!(name.len() <= 100 && target.len() <= 100);
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_mode(if kind == b'5' { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(data.len() as u64);
    header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
    header.as_mut_bytes()[157..157 + target.len()].copy_from_slice(target.as_bytes());
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(512 + data.len().div_ceil(512) * 512, 0);
    bytes
}

fn file(name: &str) -> Vec<u8> {
    member(name, b'0', b"verified content\n", "")
}
fn directory(name: &str) -> Vec<u8> {
    member(name, b'5', b"", "")
}
fn hardlink(name: &str, target: &str) -> Vec<u8> {
    member(name, b'1', b"", target)
}
fn softlink(name: &str, target: &str) -> Vec<u8> {
    member(name, b'2', b"", target)
}
fn whiteout(name: &str) -> Vec<u8> {
    member(name, b'0', b"", "")
}

fn archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut result: Vec<u8> = members.iter().flatten().copied().collect();
    result.resize(result.len() + 1024, 0);
    result
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn pax(records: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in records {
        let body = format!(" {key}={value}\n");
        let mut len = body.len() + 1;
        loop {
            let next = body.len() + len.to_string().len();
            if next == len {
                break;
            }
            len = next;
        }
        bytes.extend_from_slice(format!("{len}{body}").as_bytes());
    }
    member("PaxHeader", b'x', &bytes, "")
}

struct Fixture {
    dir: TempDir,
    locked: LockedImage,
    manifest: Value,
    config: Value,
    layers: Vec<Descriptor>,
}

impl Fixture {
    fn new(layers: Vec<(Vec<u8>, bool)>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("blobs/sha256")).unwrap();
        fs::write(
            dir.path().join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let diff_ids: Vec<_> = layers.iter().map(|(bytes, _)| digest(bytes)).collect();
        let layers: Vec<_> = layers
            .into_iter()
            .map(|(bytes, compressed)| {
                let (bytes, media) = if compressed {
                    (gzip(&bytes), OCI_GZIP)
                } else {
                    (bytes, OCI_TAR)
                };
                Self::put(dir.path(), &bytes, media)
            })
            .collect();
        let config = json!({"os":"linux", "architecture":"amd64",
            "rootfs":{"type":"layers", "diff_ids":diff_ids},
            "config":{"Env":["PATH=/usr/bin"],"Cmd":["never executed"]},
            "history":[{"created_by":"inert OCI metadata"}]});
        let config_descriptor = Self::put(
            dir.path(),
            &serde_json::to_vec(&config).unwrap(),
            OCI_CONFIG,
        );
        let manifest = json!({"schemaVersion":2, "mediaType":OCI_MANIFEST,
            "config":wire(&config_descriptor), "layers":layers.iter().map(wire).collect::<Vec<_>>()});
        let image = Self::put(
            dir.path(),
            &serde_json::to_vec(&manifest).unwrap(),
            OCI_MANIFEST,
        );
        let locked = LockedImage {
            source: "docker.io/library/debian".into(),
            image,
            source_index: None,
            libc_family: "glibc".into(),
            limits: Limits::default(),
        };
        let fixture = Self {
            dir,
            locked,
            manifest,
            config,
            layers,
        };
        fixture.write_index();
        fixture
    }

    fn raw(layers: Vec<Vec<u8>>) -> Self {
        Self::new(layers.into_iter().map(|bytes| (bytes, false)).collect())
    }

    fn put(root: &Path, bytes: &[u8], media: &str) -> Descriptor {
        let descriptor = Descriptor {
            media_type: media.into(),
            digest: digest(bytes),
            size: bytes.len() as u64,
        };
        fs::write(
            root.join("blobs/sha256").join(&descriptor.digest[7..]),
            bytes,
        )
        .unwrap();
        descriptor
    }

    fn blob(&self, descriptor: &Descriptor) -> PathBuf {
        self.dir
            .path()
            .join("blobs/sha256")
            .join(&descriptor.digest[7..])
    }

    fn write_index(&self) {
        fs::write(
            self.dir.path().join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion":2, "mediaType":OCI_INDEX, "manifests":[wire(&self.locked.image)]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn commit_manifest(&mut self) {
        self.locked.image = Self::put(
            self.dir.path(),
            &serde_json::to_vec(&self.manifest).unwrap(),
            OCI_MANIFEST,
        );
        self.write_index();
    }

    fn commit_config(&mut self) {
        let descriptor = Self::put(
            self.dir.path(),
            &serde_json::to_vec(&self.config).unwrap(),
            OCI_CONFIG,
        );
        self.manifest["config"] = wire(&descriptor);
        self.commit_manifest();
    }

    fn source_index(&mut self, platform: Value) {
        let mut selected = wire(&self.locked.image);
        selected["platform"] = platform;
        let index = json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[selected]});
        self.locked.source_index = Some(Self::put(
            self.dir.path(),
            &serde_json::to_vec(&index).unwrap(),
            OCI_INDEX,
        ));
    }

    fn passes(&self) {
        let result = verify_layout(self.dir.path(), &self.locked, "linux/amd64");
        assert!(result.is_ok(), "{result:?}");
    }

    fn fails(&self, code: &str) {
        let error = verify_layout(self.dir.path(), &self.locked, "linux/amd64").unwrap_err();
        assert_eq!(error.code, code, "{error}");
    }
}

#[test]
fn accepts_raw_gzip_full_chain_and_inert_metadata_without_extracting() {
    let first = archive(&[
        directory("."),
        directory("usr/"),
        directory("usr/bin/"),
        file("usr/bin/tool"),
        softlink("bin", "usr/bin"),
        softlink("absolute", "/usr/bin/tool"),
    ]);
    let second = archive(&[hardlink("tool-copy", "usr/bin/tool")]);
    let mut fixture = Fixture::new(vec![(first, true), (second, false)]);
    fixture.source_index(json!({"os":"linux","architecture":"amd64"}));
    fixture.passes();
    assert!(!fixture.dir.path().join("usr").exists());
    assert!(!fixture.dir.path().join("tool-copy").exists());
}

#[test]
fn retained_layout_can_include_unrelated_descriptors_without_reselecting() {
    let fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fs::write(
        fixture.dir.path().join("index.json"),
        serde_json::to_vec(&json!({
            "schemaVersion":2, "manifests":[
                {"mediaType":OCI_MANIFEST,"digest":format!("sha256:{}", "0".repeat(64)),"size":1},
                wire(&fixture.locked.image)]
        }))
        .unwrap(),
    )
    .unwrap();
    fixture.passes();
}

#[test]
fn every_raw_descriptor_is_hashed_even_when_sizes_match() {
    for selected in 0..4 {
        let mut fixture = Fixture::new(vec![(archive(&[file("file")]), true)]);
        fixture.source_index(json!({"os":"linux","architecture":"amd64"}));
        let descriptor = match selected {
            0 => fixture.locked.image.clone(),
            1 => Descriptor {
                media_type: OCI_CONFIG.into(),
                digest: fixture.manifest["config"]["digest"]
                    .as_str()
                    .unwrap()
                    .into(),
                size: fixture.manifest["config"]["size"].as_u64().unwrap(),
            },
            2 => fixture.layers[0].clone(),
            _ => fixture.locked.source_index.clone().unwrap(),
        };
        let path = fixture.blob(&descriptor);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        fixture.fails("E_TRUST");
    }
}

#[test]
fn wrong_descriptor_size_and_wrong_diff_id_fail_independently() {
    let mut fixture = Fixture::new(vec![(archive(&[file("file")]), true)]);
    fixture.manifest["layers"][0]["size"] = json!(fixture.layers[0].size + 1);
    fixture.commit_manifest();
    fixture.fails("E_TRUST");

    let mut fixture = Fixture::new(vec![(archive(&[file("file")]), true)]);
    fixture.config["rootfs"]["diff_ids"][0] = json!(format!("sha256:{}", "0".repeat(64)));
    fixture.commit_config();
    fixture.fails("E_TRUST");
}

#[test]
fn configuration_layer_order_and_count_are_binding() {
    let one = archive(&[file("one")]);
    let two = archive(&[file("two")]);
    let mut fixture = Fixture::raw(vec![one, two]);
    fixture.config["rootfs"]["diff_ids"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    fixture.commit_config();
    fixture.fails("E_TRUST");
    fixture.config["rootfs"]["diff_ids"]
        .as_array_mut()
        .unwrap()
        .pop();
    fixture.commit_config();
    fixture.fails("E_TRUST");
}

#[test]
fn platform_and_variant_cannot_be_guessed_or_discarded() {
    for platform in [
        json!({"os":"linux","architecture":"arm64"}),
        json!({"os":"linux","architecture":"amd64","variant":"v3"}),
        json!({"os":"linux","architecture":"amd64","os.features":["unsupported"]}),
    ] {
        let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
        fixture.source_index(platform);
        fixture.fails("E_ABI");
    }
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.config["architecture"] = json!("arm64");
    fixture.commit_config();
    fixture.fails("E_ABI");
    fixture.config["architecture"] = json!("amd64");
    fixture.config["variant"] = json!("v3");
    fixture.commit_config();
    fixture.fails("E_ABI");
}

#[test]
fn source_index_requires_exact_unique_platform_descriptor() {
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.source_index(Value::Null);
    fixture.fails("E_ABI");
    fixture.source_index(json!({"os":"linux","architecture":"amd64"}));
    let mut index: Value = serde_json::from_slice(
        &fs::read(fixture.blob(fixture.locked.source_index.as_ref().unwrap())).unwrap(),
    )
    .unwrap();
    let mut other = index["manifests"][0].clone();
    other["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    index["manifests"].as_array_mut().unwrap().push(other);
    fixture.locked.source_index = Some(Fixture::put(
        fixture.dir.path(),
        &serde_json::to_vec(&index).unwrap(),
        OCI_INDEX,
    ));
    fixture.fails("E_ABI");
}

#[test]
fn locked_selection_and_media_types_are_not_advisory() {
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.manifest["layers"][0]["mediaType"] =
        json!("application/vnd.oci.image.layer.v1.tar+zstd");
    fixture.commit_manifest();
    fixture.fails("E_CAPABILITY");
    fixture.manifest["layers"][0]["mediaType"] = json!(OCI_TAR);
    fixture.manifest["mediaType"] = json!("application/vnd.oci.image.index.v1+json");
    fixture.commit_manifest();
    fixture.fails("E_SCHEMA");
    fixture.manifest["mediaType"] = json!(OCI_MANIFEST);
    fixture.commit_manifest();
    fs::write(
        fixture.dir.path().join("index.json"),
        br#"{"schemaVersion":2,"manifests":[]}"#,
    )
    .unwrap();
    fixture.fails("E_LOCK");
}

#[test]
fn strict_json_rejects_duplicate_escaped_keys_and_fractional_sizes() {
    let fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fs::write(
        fixture.dir.path().join("index.json"),
        br#"{"schemaVersion":2,"schema\u0056ersion":2,"manifests":[]}"#,
    )
    .unwrap();
    fixture.fails("E_SCHEMA");
    let text = format!(
        r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{OCI_MANIFEST}","digest":"{}","size":1.0}}]}}"#,
        fixture.locked.image.digest
    );
    fs::write(fixture.dir.path().join("index.json"), text).unwrap();
    fixture.fails("E_SCHEMA");
}

#[test]
fn symlink_layout_members_and_directory_components_are_never_followed() {
    for name in ["oci-layout", "index.json", "layer", "blobs"] {
        let fixture = Fixture::raw(vec![archive(&[file("file")])]);
        let outside = tempfile::tempdir().unwrap();
        let source = match name {
            "layer" => fixture.blob(&fixture.layers[0]),
            _ => fixture.dir.path().join(name),
        };
        let moved = outside.path().join("saved");
        fs::rename(&source, &moved).unwrap();
        symlink(&moved, &source).unwrap();
        fixture.fails("E_PATH_OWNER");
    }
    let fixture = Fixture::raw(vec![archive(&[file("file")])]);
    let outside = tempfile::tempdir().unwrap();
    let alias = outside.path().join("layout");
    symlink(fixture.dir.path(), &alias).unwrap();
    let error = verify_layout(&alias, &fixture.locked, "linux/amd64").unwrap_err();
    assert_eq!(error.code, "E_CAPABILITY");
}

#[test]
fn archive_paths_have_one_explicit_root_metadata_exception() {
    for root in [".", "./"] {
        Fixture::raw(vec![archive(&[directory(root), file("file")])]).passes();
    }
    for name in [
        "/escape",
        "../escape",
        "dir/../escape",
        "./file",
        "a//b",
        "a/./b",
        "file/",
        "hidden\0suffix",
    ] {
        Fixture::raw(vec![archive(&[file(name)])]).fails("E_BUILD");
    }
    Fixture::raw(vec![archive(&[file(".")])]).fails("E_BUILD");
    Fixture::raw(vec![archive(&[directory("dir//")])]).fails("E_BUILD");
}

#[test]
fn duplicate_paths_include_directory_spelling_aliases_and_whiteouts() {
    for entries in [
        vec![file("file"), file("file")],
        vec![directory("dir"), directory("dir/")],
        vec![whiteout(".wh.gone"), whiteout(".wh.gone")],
        vec![directory("."), directory("./")],
    ] {
        Fixture::raw(vec![archive(&entries)]).fails("E_BUILD");
    }
    Fixture::raw(vec![archive(&[file("file")]), archive(&[file("file")])]).passes();
}

#[test]
fn symlink_parent_traversal_fails_within_and_across_layers() {
    Fixture::raw(vec![archive(&[softlink("link", "dir"), file("link/file")])]).fails("E_BUILD");
    Fixture::raw(vec![
        archive(&[softlink("link", "/")]),
        archive(&[file("link/file")]),
    ])
    .fails("E_BUILD");
    Fixture::raw(vec![archive(&[
        softlink("link", "dir"),
        whiteout("link/.wh.file"),
    ])])
    .fails("E_BUILD");
    Fixture::raw(vec![archive(&[file("parent"), file("parent/file")])]).fails("E_BUILD");
}

#[test]
fn symlink_targets_are_in_view_but_relative_escape_is_rejected() {
    Fixture::raw(vec![archive(&[
        directory("dir"),
        softlink("dir/up", "../target"),
        softlink("absolute", "/etc/passwd"),
        softlink("root", "/"),
    ])])
    .passes();
    for (name, target) in [
        ("escape", "../host"),
        ("dir/escape", "../../host"),
        ("absolute", "/../host"),
        ("empty", ""),
        ("nul", "a\0b"),
    ] {
        let fixture = Fixture::raw(vec![archive(&[softlink(name, target)])]);
        let error = verify_layout(fixture.dir.path(), &fixture.locked, "linux/amd64").unwrap_err();
        assert_eq!(error.code, "E_BUILD", "{name}: {error}");
    }
}

#[test]
fn hardlinks_require_previous_regular_targets_not_forward_or_symlink_targets() {
    Fixture::raw(vec![
        archive(&[file("source"), hardlink("copy", "source")]),
        archive(&[hardlink("cross-layer", "copy")]),
    ])
    .passes();
    for entries in [
        vec![hardlink("copy", "future"), file("future")],
        vec![softlink("source", "missing"), hardlink("copy", "source")],
        vec![directory("source"), hardlink("copy", "source")],
        vec![hardlink("copy", "copy")],
        vec![hardlink("copy", "missing")],
    ] {
        Fixture::raw(vec![archive(&entries)]).fails("E_BUILD");
    }
    for target in ["/etc/passwd", "../outside", "./source"] {
        Fixture::raw(vec![archive(&[hardlink("copy", target)])]).fails("E_BUILD");
    }
    Fixture::raw(vec![
        archive(&[file("source"), softlink("dir", "/")]),
        archive(&[hardlink("copy", "dir/source")]),
    ])
    .fails("E_BUILD");
}

#[test]
fn whiteouts_only_delete_lower_entries_even_after_same_layer_additions() {
    for after in [false, true] {
        let replacement = file("file");
        let marker = whiteout(".wh.file");
        let update = if after {
            vec![replacement, marker]
        } else {
            vec![marker, replacement]
        };
        Fixture::raw(vec![
            archive(&[file("file")]),
            archive(&update),
            archive(&[hardlink("proof", "file")]),
        ])
        .passes();
    }
    Fixture::raw(vec![
        archive(&[file("file")]),
        archive(&[whiteout(".wh.file")]),
        archive(&[hardlink("proof", "file")]),
    ])
    .fails("E_BUILD");
    Fixture::raw(vec![
        archive(&[file("source"), hardlink("copy", "source")]),
        archive(&[whiteout(".wh.source")]),
        archive(&[hardlink("proof", "copy")]),
    ])
    .passes();
}

#[test]
fn opaque_whiteouts_preserve_new_children_and_remove_old_descendants() {
    for after in [false, true] {
        let new = file("dir/new");
        let marker = whiteout("dir/.wh..wh..opq");
        let update = if after {
            vec![new, marker]
        } else {
            vec![marker, new]
        };
        Fixture::raw(vec![
            archive(&[file("dir/old")]),
            archive(&update),
            archive(&[hardlink("proof", "dir/new")]),
        ])
        .passes();
        Fixture::raw(vec![
            archive(&[file("dir/old")]),
            archive(&update),
            archive(&[hardlink("proof", "dir/old")]),
        ])
        .fails("E_BUILD");
    }
    Fixture::raw(vec![
        archive(&[file("old")]),
        archive(&[file("new"), whiteout(".wh..wh..opq")]),
        archive(&[hardlink("proof", "new")]),
    ])
    .passes();
}

#[test]
fn replacement_removes_lower_descendants_and_can_recreate_whiteouted_symlinks() {
    Fixture::raw(vec![
        archive(&[file("dir/old")]),
        archive(&[file("dir")]),
        archive(&[hardlink("proof", "dir/old")]),
    ])
    .fails("E_BUILD");
    Fixture::raw(vec![
        archive(&[softlink("dir", "elsewhere")]),
        archive(&[whiteout(".wh.dir"), directory("dir"), file("dir/new")]),
        archive(&[hardlink("proof", "dir/new")]),
    ])
    .passes();
}

#[test]
fn invalid_whiteouts_are_not_materializable_files() {
    for entry in [
        whiteout(".wh."),
        whiteout(".wh.."),
        whiteout(".wh..."),
        whiteout(".wh..wh.ambiguous"),
        file(".wh.file"),
        directory(".wh.file"),
        softlink(".wh.file", "target"),
    ] {
        Fixture::raw(vec![archive(&[entry])]).fails("E_BUILD");
    }
}

#[test]
fn special_sparse_and_privileged_extended_metadata_fail_closed() {
    for kind in [b'3', b'4', b'6', b'7', b'S', b'V', b's'] {
        Fixture::raw(vec![archive(&[member("special", kind, b"", "")])]).fails("E_BUILD");
    }
    for (key, code) in [
        ("SCHILY.xattr.security.capability", "E_TRUST"),
        ("SCHILY.xattr.trusted.overlay.opaque", "E_TRUST"),
        ("GNU.sparse.map", "E_TRUST"),
        ("SCHILY.xattr.user.comment", "E_CAPABILITY"),
        ("SCHILY.xattr.user.rootlesscontainers", "E_CAPABILITY"),
        ("LIBARCHIVE.xattr.security.capability", "E_TRUST"),
        ("LIBARCHIVE.xattr.user.comment", "E_CAPABILITY"),
        ("size", "E_CAPABILITY"),
    ] {
        Fixture::raw(vec![archive(&[pax(&[(key, "1")]), file("file")])]).fails(code);
    }
}

#[test]
fn pax_and_gnu_names_are_preflighted_without_parser_ambiguity() {
    let long = "a".repeat(120);
    Fixture::raw(vec![archive(&[
        pax(&[("path", &long), ("mtime", "123.456")]),
        file("short"),
    ])])
    .passes();
    let mut gnu_name = long.as_bytes().to_vec();
    gnu_name.push(0);
    Fixture::raw(vec![archive(&[
        member("LongName", b'L', &gnu_name, ""),
        file("short"),
    ])])
    .passes();
    Fixture::raw(vec![archive(&[
        pax(&[("path", "../escape")]),
        file("short"),
    ])])
    .fails("E_BUILD");
    Fixture::raw(vec![archive(&[
        pax(&[("path", "one"), ("path", "two")]),
        file("short"),
    ])])
    .fails("E_BUILD");
    Fixture::raw(vec![archive(&[
        pax(&[("path", "one")]),
        member("LongName", b'L', &gnu_name, ""),
        file("short"),
    ])])
    .fails("E_BUILD");
    Fixture::raw(vec![archive(&[member("LongName", b'L', &gnu_name, "")])]).fails("E_BUILD");
    Fixture::raw(vec![archive(&[
        member("global", b'g', b"", ""),
        file("file"),
    ])])
    .fails("E_CAPABILITY");
}

#[test]
fn archive_bounds_include_padding_metadata_implicit_directories_and_all_layers() {
    let data = archive(&[file("file")]);
    let mut fixture = Fixture::raw(vec![data.clone()]);
    fixture.locked.limits.max_expanded_bytes = data.len() as u64 - 1;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::new(vec![(data.clone(), true)]);
    fixture.locked.limits.max_expansion_ratio = 1;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![data.clone(), data.clone()]);
    fixture.locked.limits.max_expanded_bytes = data.len() as u64;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![data]);
    fixture.locked.limits.max_blob_bytes = 1;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[file("long-name")])]);
    fixture.locked.limits.max_path_bytes = 4;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.locked.limits.max_file_bytes = 1;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[file("one"), file("two")])]);
    fixture.locked.limits.max_entries = 1;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[file("a/b/c/file")])]);
    fixture.locked.limits.max_entries = 2;
    fixture.fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[pax(&[("mtime", "0")]), file("file")])]);
    fixture.locked.limits.max_entries = 1;
    fixture.fails("E_BUILD");
    let deep = std::iter::repeat_n("a", 65).collect::<Vec<_>>().join("/");
    Fixture::raw(vec![archive(&[pax(&[("path", &deep)]), file("short")])]).fails("E_BUILD");
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.locked.limits.timeout_seconds = 0;
    fixture.fails("E_BUILD");
}

#[test]
fn full_uncompressed_stream_includes_padding_and_all_gzip_members() {
    let data = archive(&[file("file")]);
    let mut padded = data.clone();
    padded.resize(padded.len() + 1024, 0);
    let mut fixture = Fixture::new(vec![(padded.clone(), true)]);
    fixture.passes();
    fixture.config["rootfs"]["diff_ids"][0] = json!(digest(&data));
    fixture.commit_config();
    fixture.fails("E_TRUST");

    let mut fixture = Fixture::new(vec![(padded.clone(), true)]);
    let mut compressed = gzip(&padded[..512]);
    compressed.extend(gzip(&padded[512..]));
    let layer = Fixture::put(fixture.dir.path(), &compressed, OCI_GZIP);
    fixture.manifest["layers"][0] = wire(&layer);
    fixture.commit_manifest();
    fixture.passes();
    compressed.extend_from_slice(b"not another gzip member");
    let layer = Fixture::put(fixture.dir.path(), &compressed, OCI_GZIP);
    fixture.manifest["layers"][0] = wire(&layer);
    fixture.commit_manifest();
    fixture.fails("E_BUILD");
}

#[test]
fn tar_truncation_and_hidden_second_archives_are_rejected() {
    let data = archive(&[file("file")]);
    for removed in [1, 512, 1024] {
        let mut truncated = data.clone();
        truncated.truncate(truncated.len() - removed);
        let fixture = Fixture::raw(vec![truncated]);
        let error = verify_layout(fixture.dir.path(), &fixture.locked, "linux/amd64").unwrap_err();
        assert_eq!(error.code, "E_BUILD");
    }
    let mut hidden = data;
    hidden.extend(archive(&[file("hidden")]));
    Fixture::raw(vec![hidden]).fails("E_BUILD");
}

#[test]
fn privileged_modes_are_admissible_only_as_audit_input_for_later_stripping() {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("privileged").unwrap();
    header.set_size(0);
    header.set_mode(0o6755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    Fixture::raw(vec![archive(&[header.as_bytes().to_vec()])]).passes();
}

#[test]
fn reserved_whiteout_names_cannot_be_implicit_directories() {
    Fixture::raw(vec![archive(&[file(".wh.parent/child")])]).fails("E_BUILD");
    Fixture::raw(vec![archive(&[whiteout("dir/.wh.parent/.wh.child")])]).fails("E_BUILD");
}

#[test]
fn embedded_descriptor_data_and_urls_never_replace_required_local_blobs() {
    let mut fixture = Fixture::raw(vec![archive(&[file("file")])]);
    fixture.manifest["config"]["data"] = json!("AAAA");
    fixture.manifest["config"]["urls"] = json!(["https://never-contact.invalid/config"]);
    fixture.commit_manifest();
    fixture.passes();
    let config_path = fixture
        .dir
        .path()
        .join("blobs/sha256")
        .join(&fixture.manifest["config"]["digest"].as_str().unwrap()[7..]);
    fs::remove_file(config_path).unwrap();
    fixture.fails("E_PATH_OWNER");
}

#[test]
fn gzip_checksums_and_truncation_fail_even_when_raw_descriptors_are_correct() {
    for truncate in [false, true] {
        let mut fixture = Fixture::new(vec![(archive(&[file("file")]), true)]);
        let mut compressed = fs::read(fixture.blob(&fixture.layers[0])).unwrap();
        if truncate {
            compressed.truncate(compressed.len() - 4);
        } else {
            let crc_start = compressed.len() - 8;
            compressed[crc_start] ^= 1;
        }
        let descriptor = Fixture::put(fixture.dir.path(), &compressed, OCI_GZIP);
        fixture.manifest["layers"][0] = wire(&descriptor);
        fixture.commit_manifest();
        let error = verify_layout(fixture.dir.path(), &fixture.locked, "linux/amd64").unwrap_err();
        assert_eq!(error.code, "E_BUILD", "{error}");
    }
}

#[test]
fn duplicate_locked_index_entries_and_descriptor_aliases_fail_closed() {
    let fixture = Fixture::raw(vec![archive(&[file("file")])]);
    for change_size in [false, true] {
        let mut alias = wire(&fixture.locked.image);
        if change_size {
            alias["size"] = json!(fixture.locked.image.size + 1);
        }
        let entries = if change_size {
            vec![alias]
        } else {
            vec![alias.clone(), alias]
        };
        fs::write(
            fixture.dir.path().join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion":2,"mediaType":OCI_INDEX,"manifests":entries
            }))
            .unwrap(),
        )
        .unwrap();
        fixture.fails("E_LOCK");
    }
}
