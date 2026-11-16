use super::*;

fn u16_at(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn utf16_until_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16(&units).unwrap()
}

/// Where LinkInfo starts: after the header and the ID list, if any.
fn link_info_offset(bytes: &[u8]) -> usize {
    if u32_at(bytes, 20) & HAS_LINK_TARGET_ID_LIST == 0 {
        0x4C
    } else {
        0x4C + 2 + u16_at(bytes, 0x4C)
    }
}

/// The ID list's items: each class type, with the drive's or entry's name.
fn id_items(bytes: &[u8]) -> Vec<(u8, String)> {
    let size = u16_at(bytes, 0x4C);
    let list = &bytes[0x4E..0x4E + size];
    let mut items = Vec::new();
    let mut offset = 0;
    loop {
        let item = u16_at(list, offset);
        if item == 0 {
            break;
        }
        let data = &list[offset + 2..offset + item];
        let name = match data[0] {
            0x35 | 0x36 => utf16_until_nul(&data[12..]),
            0x2F => String::from_utf8(data[1..4].to_vec()).unwrap(),
            _ => String::new(),
        };
        items.push((data[0], name));
        offset += item;
    }
    assert_eq!(offset + 2, size, "the list ends where its size says");
    items
}

/// The StringData entries after LinkInfo.
fn strings(bytes: &[u8]) -> Vec<String> {
    let info = link_info_offset(bytes);
    let mut offset = info + u32_at(bytes, info) as usize;
    let mut found = Vec::new();
    while offset + 2 <= bytes.len() - 4 {
        let count = u16_at(bytes, offset);
        offset += 2;
        found.push(utf16_until_nul(&bytes[offset..offset + count * 2]));
        offset += count * 2;
    }
    found
}

fn link(target: &str, arguments: &[&str]) -> Link {
    Link {
        target: PathBuf::from(target),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        working_dir: PathBuf::from(r"C:\Users\José"),
        description: "FactorSeal Desktop".to_owned(),
    }
}

#[test]
fn a_link_holds_its_target_strings_and_sizes() {
    let link = link(
        r"C:\Users\José\AppData\Local\Programs\FactorSeal\factorseal-desktop.exe",
        &["--background"],
    );
    let bytes = link.to_bytes();
    assert_eq!(u32_at(&bytes, 0), 0x4C);
    assert_eq!(&bytes[4..20], &LINK_CLSID);
    assert_eq!(
        u32_at(&bytes, 20),
        HAS_LINK_TARGET_ID_LIST
            | HAS_LINK_INFO
            | HAS_NAME
            | HAS_WORKING_DIR
            | HAS_ARGUMENTS
            | HAS_ICON_LOCATION
            | IS_UNICODE
    );
    // LinkInfo: its offsets point at the paths.
    let info = &bytes[link_info_offset(&bytes)..];
    let size = u32_at(info, 0) as usize;
    assert_eq!(u32_at(info, 4), LINK_INFO_HEADER);
    let ansi = u32_at(info, 16) as usize;
    let ansi_end = ansi + info[ansi..].iter().position(|&b| b == 0).unwrap();
    assert_eq!(
        std::str::from_utf8(&info[ansi..ansi_end]).unwrap(),
        r"C:\Users\Jos?\AppData\Local\Programs\FactorSeal\factorseal-desktop.exe"
    );
    let unicode = u32_at(info, 28) as usize;
    assert_eq!(
        utf16_until_nul(&info[unicode..size]),
        link.target.to_string_lossy()
    );
    assert_eq!(
        strings(&bytes),
        [
            "FactorSeal Desktop",
            r"C:\Users\José",
            "--background",
            r"C:\Users\José\AppData\Local\Programs\FactorSeal\factorseal-desktop.exe",
        ]
    );
    assert_eq!(u32_at(&bytes, bytes.len() - 4), 0);
    // Adoption finds the installer's own shortcuts.
    assert!(crate::engine::holds_path(
        &bytes,
        &link.target.to_string_lossy().to_lowercase()
    ));
}

#[test]
fn the_id_list_names_the_drive_folders_and_file() {
    let local = link(r"c:\Users\José\FactorSeal\factorseal-desktop.exe", &[]);
    assert_eq!(
        id_items(&local.to_bytes()),
        [
            (0x1F, String::new()),
            (0x2F, r"C:\".to_owned()),
            (0x35, "Users".to_owned()),
            (0x35, "José".to_owned()),
            (0x35, "FactorSeal".to_owned()),
            (0x36, "factorseal-desktop.exe".to_owned()),
        ]
    );
    // Not on a drive letter: LinkInfo alone.
    let unc = link(r"\\server\share\x.exe", &[]);
    assert_eq!(u32_at(&unc.to_bytes(), 20) & HAS_LINK_TARGET_ID_LIST, 0);
}

#[test]
fn a_link_without_arguments_has_no_argument_string() {
    let bytes = link(r"C:\FactorSeal\factorseal-desktop.exe", &[]).to_bytes();
    assert_eq!(u32_at(&bytes, 20) & HAS_ARGUMENTS, 0);
    assert_eq!(strings(&bytes).len(), 3);
}

#[test]
fn a_target_longer_than_max_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let long = link(&format!(r"C:\{}\x.exe", "d".repeat(MAX_TARGET)), &[]);
    assert!(long.write(&dir.path().join("x.lnk")).is_err());
    assert!(!dir.path().join("x.lnk").exists());
    let fine = link(r"C:\FactorSeal\factorseal-desktop.exe", &[]);
    fine.write(&dir.path().join("x.lnk")).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("x.lnk")).unwrap(),
        fine.to_bytes()
    );
    assert!(!dir.path().join("x.lnk.new").exists());
}

#[test]
fn arguments_are_quoted_as_the_c_runtime_splits_them() {
    let cases: [(&[&str], &str); 7] = [
        (&["--background"], "--background"),
        (&["--open", "wsl-keyrings"], "--open wsl-keyrings"),
        (&["a b"], r#""a b""#),
        (&[""], r#""""#),
        (&[r#"say "hi""#], r#""say \"hi\"""#),
        (&[r"C:\dir with space\"], r#""C:\dir with space\\""#),
        (&[r"C:\plain\"], r"C:\plain\"),
    ];
    for (arguments, expected) in cases {
        let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
        assert_eq!(command_line(&arguments), expected, "{arguments:?}");
    }
}
