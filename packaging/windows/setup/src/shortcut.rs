//! Shell links (`.lnk`), written directly in the documented format
//! ([MS-SHLLINK]) instead of through COM, so the installer needs no unsafe
//! code and doesn't run another program to make them.
//!
//! A link here carries its target twice: as an item ID list in the simple
//! form the shell itself makes (`SHSimpleIDListFromPath`: "This PC", the
//! drive, then each folder and the file, named in UTF-16), which is what
//! Windows reports as the target; and as LinkInfo, the local path in ANSI
//! and UTF-16. Its strings give the description, working directory,
//! arguments and icon. Checked natively on 2026-11-16: without the ID
//! list the link opens, but WScript.Shell and Shell.Application read an
//! empty target, as Explorer's Properties would show it.
//!
//! [MS-SHLLINK]: https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/

use std::path::{Path, PathBuf};

/// The shell link class, `00021401-0000-0000-C000-000000000046`.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// "This PC", the root of local paths in the shell's namespace,
/// `20D04FE0-3AEA-1069-A2D8-08002B30309D`.
const MY_COMPUTER: [u8; 16] = [
    0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D,
];

const HAS_LINK_TARGET_ID_LIST: u32 = 0x01;
const HAS_LINK_INFO: u32 = 0x02;
const HAS_NAME: u32 = 0x04;
const HAS_WORKING_DIR: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON_LOCATION: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const SW_SHOWNORMAL: u32 = 1;
/// LinkInfo flag: a volume ID and a local base path follow.
const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x01;
const DRIVE_FIXED: u32 = 3;
/// LinkInfo header size with the Unicode path offsets.
const LINK_INFO_HEADER: u32 = 0x24;

/// The longest target path, in UTF-16 units (`MAX_PATH` without its NUL).
pub const MAX_TARGET: usize = 259;

/// What a shortcut opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// An absolute path to the program.
    pub target: PathBuf,
    pub arguments: Vec<String>,
    pub working_dir: PathBuf,
    /// The tooltip.
    pub description: String,
}

impl Link {
    /// The link's bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let target = self.target.to_string_lossy();
        let id_list = id_list(&target);
        let mut flags = HAS_LINK_INFO | HAS_NAME | HAS_WORKING_DIR | HAS_ICON_LOCATION | IS_UNICODE;
        if id_list.is_some() {
            flags |= HAS_LINK_TARGET_ID_LIST;
        }
        if !self.arguments.is_empty() {
            flags |= HAS_ARGUMENTS;
        }
        let mut bytes = Vec::new();
        // ShellLinkHeader.
        put_u32(&mut bytes, 0x4C);
        bytes.extend_from_slice(&LINK_CLSID);
        put_u32(&mut bytes, flags);
        put_u32(&mut bytes, FILE_ATTRIBUTE_NORMAL);
        bytes.extend_from_slice(&[0; 24]); // creation, access and write times
        put_u32(&mut bytes, 0); // file size
        put_u32(&mut bytes, 0); // icon index
        put_u32(&mut bytes, SW_SHOWNORMAL);
        bytes.extend_from_slice(&[0; 2 + 2 + 4 + 4]); // hot key, reserved
        if let Some(id_list) = id_list {
            bytes.extend_from_slice(&id_list);
        }
        bytes.extend_from_slice(&link_info(&target));
        // StringData, in the order the format fixes.
        put_string(&mut bytes, &self.description);
        put_string(&mut bytes, &self.working_dir.to_string_lossy());
        if !self.arguments.is_empty() {
            put_string(&mut bytes, &command_line(&self.arguments));
        }
        put_string(&mut bytes, &target);
        put_u32(&mut bytes, 0); // terminal block
        bytes
    }

    /// Write the link to `path` through a temporary file beside it. A
    /// target longer than [`MAX_TARGET`] is refused.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        if self.target.to_string_lossy().encode_utf16().count() > MAX_TARGET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is too long for a shortcut", self.target.display()),
            ));
        }
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".new");
        let temporary = PathBuf::from(temporary);
        std::fs::write(&temporary, self.to_bytes())?;
        std::fs::rename(&temporary, path)
    }
}

/// The target's item ID list, sized: "This PC", the drive, then a file
/// entry with a UTF-16 name (class type flag 0x04) per folder and for the
/// file. `None` for a path not on a drive letter (LinkInfo alone then).
fn id_list(target: &str) -> Option<Vec<u8>> {
    let (drive, rest) = target.split_once('\\')?;
    let letter = drive.strip_suffix(':').filter(|letter| {
        letter.len() == 1 && letter.bytes().all(|byte| byte.is_ascii_alphabetic())
    })?;
    let parts: Vec<&str> = rest.split('\\').filter(|part| !part.is_empty()).collect();
    let (file, folders) = parts.split_last()?;

    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut root = vec![0x1F, 0x50];
    root.extend_from_slice(&MY_COMPUTER);
    items.push(root);
    let mut volume = vec![0x2F];
    volume.extend_from_slice(format!("{}:\\", letter.to_ascii_uppercase()).as_bytes());
    volume.resize(23, 0);
    items.push(volume);
    let entries = folders
        .iter()
        .map(|folder| (*folder, true))
        .chain(std::iter::once((*file, false)));
    for (name, folder) in entries {
        let mut item = vec![if folder { 0x35 } else { 0x36 }, 0];
        put_u32(&mut item, 0); // size
        put_u32(&mut item, 0); // modification time
        item.extend_from_slice(&(if folder { 0x10_u16 } else { 0x20 }).to_le_bytes());
        item.extend_from_slice(&utf16(name));
        item.extend_from_slice(&[0, 0]);
        items.push(item);
    }
    let mut list = Vec::new();
    for item in &items {
        list.extend_from_slice(&u16::try_from(item.len() + 2).ok()?.to_le_bytes());
        list.extend_from_slice(item);
    }
    list.extend_from_slice(&[0, 0]);
    let mut bytes = u16::try_from(list.len()).ok()?.to_le_bytes().to_vec();
    bytes.extend_from_slice(&list);
    Some(bytes)
}

/// LinkInfo for a target on a fixed local drive.
fn link_info(target: &str) -> Vec<u8> {
    // VolumeID: no serial number, an empty ANSI label.
    let mut volume = Vec::new();
    put_u32(&mut volume, 0x11);
    put_u32(&mut volume, DRIVE_FIXED);
    put_u32(&mut volume, 0);
    put_u32(&mut volume, 0x10);
    volume.push(0);
    // The ANSI path can't hold every character; Windows uses the UTF-16 one.
    let mut ansi: Vec<u8> = target
        .chars()
        .map(|c| u8::try_from(c).ok().filter(u8::is_ascii).unwrap_or(b'?'))
        .collect();
    ansi.push(0);
    let suffix = [0_u8];
    let mut unicode = utf16(target);
    unicode.extend_from_slice(&[0, 0]);
    let unicode_suffix = [0_u8, 0];

    let volume_offset = LINK_INFO_HEADER;
    let ansi_offset = volume_offset + len(&volume);
    let suffix_offset = ansi_offset + len(&ansi);
    let unicode_offset = suffix_offset + len(&suffix);
    let unicode_suffix_offset = unicode_offset + len(&unicode);
    let size = unicode_suffix_offset + len(&unicode_suffix);

    let mut info = Vec::new();
    put_u32(&mut info, size);
    put_u32(&mut info, LINK_INFO_HEADER);
    put_u32(&mut info, VOLUME_ID_AND_LOCAL_BASE_PATH);
    put_u32(&mut info, volume_offset);
    put_u32(&mut info, ansi_offset);
    put_u32(&mut info, 0); // no network path
    put_u32(&mut info, suffix_offset);
    put_u32(&mut info, unicode_offset);
    put_u32(&mut info, unicode_suffix_offset);
    for part in [&volume[..], &ansi, &suffix, &unicode, &unicode_suffix] {
        info.extend_from_slice(part);
    }
    info
}

fn len(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX)
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A StringData entry: a count of UTF-16 units, then the units, no NUL.
fn put_string(bytes: &mut Vec<u8>, text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(usize::from(u16::MAX)).collect();
    bytes.extend_from_slice(&u16::try_from(units.len()).unwrap_or(u16::MAX).to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
}

/// `arguments` as one Windows command line, quoted the way the C runtime
/// (and Rust's `std::env::args`) splits it back.
#[must_use]
pub fn command_line(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
        return argument.to_owned();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0;
    for c in argument.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Backslashes before a quote are doubled, and the quote escaped.
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(c);
            }
        }
    }
    // Before the closing quote, too.
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests;
