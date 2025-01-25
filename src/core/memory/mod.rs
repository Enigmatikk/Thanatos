use std::collections::HashMap;
use lazy_static::lazy_static;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    PAGE_PROTECTION_FLAGS, PAGE_TYPE,
    VIRTUAL_ALLOCATION_TYPE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, MEM_COMMIT
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
};
use std::path::PathBuf;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use anyhow::Result;
use windows::core::Error;

lazy_static! {
    static ref BATCH_CACHE: std::sync::Mutex<HashMap<u64, Vec<MemoryBatch>>> = std::sync::Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub state: VIRTUAL_ALLOCATION_TYPE,
    pub protection: PAGE_PROTECTION_FLAGS,
    pub allocation_type: PAGE_TYPE,
    pub is_executable: bool,
    pub is_writable: bool,
}

impl MemoryRegion {
    fn eq(&self, other: &Self) -> bool {
        self.base_address == other.base_address
            && self.size == other.size
            && self.state == other.state
            && self.protection == other.protection
            && self.allocation_type == other.allocation_type
            && self.is_executable == other.is_executable
            && self.is_writable == other.is_writable
    }
}

pub struct MemoryAccess {
    handle: HANDLE,
    pid: u32,
}

impl MemoryAccess {
    pub fn new(pid: u32) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        }?;
    
        Ok(Self { handle, pid })
    }
    pub fn dump_region(pid: u32, region: &MemoryRegion) -> Result<PathBuf> {
        let access = Self::new(pid)?;
        let mut buffer = vec![0u8; region.size];
        let mut bytes_read = 0;
    
        unsafe {
            ReadProcessMemory(
                access.handle,
                region.base_address as *const _,
                buffer.as_mut_ptr() as *mut _,
                region.size,
                Some(&mut bytes_read),
            )?;
        }
    
        buffer.truncate(bytes_read);
    
        let dump_dir = std::env::current_dir()?.join("dumps");
        std::fs::create_dir_all(&dump_dir)?;
    
        let filename = format!("dump_{:x}_{}.bin", region.base_address, chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let path = dump_dir.join(filename);
        
        std::fs::write(&path, &buffer)?;
        Ok(path)
    }
    pub fn get_memory_map(pid: u32) -> Result<Vec<MemoryRegion>> {
        let access = Self::new(pid)?;
        let mut address = 0usize;
        let mut regions = Vec::new();

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            
            let result = unsafe {
                VirtualQueryEx(
                    access.handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            let is_executable = {
                let protect = mbi.Protect.0;
                protect == PAGE_EXECUTE.0 || 
                protect == PAGE_EXECUTE_READ.0 || 
                protect == PAGE_EXECUTE_READWRITE.0
            };
            
            let is_writable = {
                let protect = mbi.Protect.0;
                protect == PAGE_READWRITE.0 || 
                protect == PAGE_EXECUTE_READWRITE.0
            };
            let region = MemoryRegion {
                base_address: mbi.BaseAddress as usize,
                size: mbi.RegionSize,
                state: VIRTUAL_ALLOCATION_TYPE(mbi.State.0),
                protection: PAGE_PROTECTION_FLAGS(mbi.Protect.0),
                allocation_type: PAGE_TYPE(mbi.Type.0),
                is_executable,
                is_writable,
            };

            regions.push(region);

            address = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if address >= 0x7FFF_FFFF_FFFF {
                break;
            }
        }

        Ok(regions)
    }

    pub fn read_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
        let access = Self::new(pid)?;
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;
    
        unsafe {
            ReadProcessMemory(
                access.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )?;  
        }
    
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

impl Drop for MemoryAccess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

pub struct MemoryAnalysis {
    pub entropy: f64,
    pub contains_shellcode: bool,
    pub interesting_strings: Vec<String>,
    pub potential_passwords: Vec<String>,
    pub file_signatures: Vec<String>,
    pub compression_ratio: f64,
    pub byte_distribution: std::collections::HashMap<u8, f64>,
    pub timestamp: std::time::SystemTime,
}

impl MemoryAnalysis {
    fn is_stale(&self) -> bool {
        self.timestamp.elapsed().unwrap_or_default().as_secs() > 30
    }
}

pub fn search_memory(process_id: u32, pattern: &[u8]) -> Result<Vec<MemoryPattern>> {
    let regions = MemoryAccess::get_memory_map(process_id)?;
    let mut matches = Vec::new();

    for region in regions {
        if region.state != VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0) {
            continue;
        }

        if let Ok(data) = MemoryAccess::read_memory(process_id, region.base_address, region.size) {
            for (i, window) in data.windows(pattern.len()).enumerate() {
                if window == pattern {
                    matches.push(MemoryPattern {
                        offset: region.base_address + i,
                        size: pattern.len(),
                        matches: window.to_vec(),
                    });
                }
            }
        }
    }

    Ok(matches)
}

pub fn quick_analyze_region(process_id: u32, region: &MemoryRegion) -> Result<std::collections::HashMap<String, String>> {
    let mut result = std::collections::HashMap::new();
    
    if region.state != VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0) {
        return Ok(std::collections::HashMap::from([
            ("status".to_string(), "skipped".to_string()),
            ("reason".to_string(), "not committed".to_string()),
        ]));
    }

    if let Ok(data) = MemoryAccess::read_memory(process_id, region.base_address, region.size) {
        let signatures = detect_file_signatures(&data);
        if !signatures.is_empty() {
            result.insert("file_signatures".to_string(), signatures.join(", "));
        }

        result.insert("is_executable".to_string(), region.is_executable.to_string());
        result.insert("is_writable".to_string(), region.is_writable.to_string());
        
        
        let analysis = analyze_memory_data(&data);
        result.extend(analysis);
    }
    
    Ok(result)
}

pub fn analyze_region(process_id: u32, region: &MemoryRegion) -> Result<std::collections::HashMap<String, String>> {
    let mut analysis = std::collections::HashMap::new();
    
    if let Ok(data) = MemoryAccess::read_memory(process_id, region.base_address, region.size) {
        let text = String::from_utf8_lossy(&data).to_string();
        analysis.insert("text_content".to_string(), text);
        
        
    }
    
    Ok(analysis)
}

fn analyze_memory_data(data: &[u8]) -> std::collections::HashMap<String, String> {
    let mut results = std::collections::HashMap::new();
    
    results.insert("entropy".to_string(), format!("{:.2}", calculate_entropy(data)));
    results.insert("contains_shellcode".to_string(), contains_shellcode(data).to_string());
    
    let strings = extract_strings(data);
    if !strings.is_empty() {
        results.insert("strings".to_string(), strings.join("\n"));
    }
    
    let passwords = find_potential_passwords(data);
    if !passwords.is_empty() {
        results.insert("passwords".to_string(), passwords.join("\n"));
    }
    
    let signatures = detect_file_signatures(data);
    if !signatures.is_empty() {
        results.insert("signatures".to_string(), signatures.join(", "));
    }
    
    results.insert("compression_ratio".to_string(), format!("{:.2}", calculate_compression_ratio(data)));
    
    let distribution = analyze_byte_distribution(data);
    results.insert("byte_distribution".to_string(), format!("{:?}", distribution));
    
    results
}

fn find_potential_passwords(data: &[u8]) -> Vec<String> {
    let mut passwords = std::collections::HashSet::new();
    
    
    let text = String::from_utf8_lossy(data).to_string();
    for line in text.lines() {
        if line.contains("pass") || line.contains("pwd") {
            passwords.insert(line.to_string());
        }
    }
    
    passwords.into_iter().collect()
}

fn detect_file_signatures(data: &[u8]) -> Vec<String> {
    let mut signatures = Vec::new();
    
    
    let patterns = [
        (&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A][..], "PNG Image"),
        (&[0x47, 0x49, 0x46, 0x38, 0x37, 0x61][..], "GIF Image"),
        (&[0x47, 0x49, 0x46, 0x38, 0x39, 0x61][..], "GIF Image"),
        (&[0xFF, 0xD8, 0xFF][..], "JPEG Image"),
        (&[0x50, 0x4B, 0x03, 0x04][..], "ZIP Archive"),
        (&[0x4D, 0x5A][..], "Windows Executable"),
        (&[0x25, 0x50, 0x44, 0x46][..], "PDF Document"),
    ];

    for (pattern, desc) in patterns {
        if data.len() >= pattern.len() && data.starts_with(pattern) {
            signatures.push(desc.to_string());
        }
    }

    signatures
}

fn calculate_compression_ratio(data: &[u8]) -> f64 {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(data).is_err() {
        return 1.0;
    }

    if let Ok(compressed) = encoder.finish() {
        data.len() as f64 / compressed.len() as f64
    } else {
        1.0
    }
}

fn analyze_byte_distribution(data: &[u8]) -> std::collections::HashMap<u8, f64> {
    let mut counts = std::collections::HashMap::new();
    let len = data.len() as f64;

    for &byte in data {
        *counts.entry(byte).or_insert(0.0) += 1.0;
    }

    for count in counts.values_mut() {
        *count /= len;
    }

    counts
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn contains_shellcode(data: &[u8]) -> bool {
    
    let patterns = [
        (&[0x55, 0x8B, 0xEC][..], "push ebp; mov ebp, esp"),
        (&[0x33, 0xC0][..], "xor eax, eax"),
        (&[0x89, 0xE5][..], "mov ebp, esp"),
        (&[0x31, 0xC0][..], "xor eax, eax"),
    ];

    for pattern in patterns {
        if data.windows(pattern.0.len()).any(|window| window == pattern.0) {
            return true;
        }
    }
    false
}

fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_alphanumeric() || byte.is_ascii_punctuation() {
            current.push(byte);
        } else if !current.is_empty() {
            if current.len() >= 4 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }

    strings
}

#[derive(Debug, Clone)]
pub struct MemoryBatch {
    pub region: MemoryRegion,
    pub data: Vec<u8>,
    pub analysis: HashMap<String, String>,
}

impl PartialEq for MemoryBatch {
    fn eq(&self, other: &Self) -> bool {
        self.region == other.region
    }
}

impl Eq for MemoryBatch {}

pub fn analyze_memory_batch(
    process_id: u32,
    region: &MemoryRegion,
    batch_size: usize,
    progress_callback: impl Fn(f32),
) -> Result<Vec<MemoryBatch>> {
    let mut batches = Vec::new();
    let total_size = region.size;
    let mut remaining_size = total_size;
    let mut current_address = region.base_address;

    while remaining_size > 0 {
        let batch_size = batch_size.min(remaining_size);
        
        if let Ok(mut buffer) = MemoryAccess::read_memory(process_id, current_address, batch_size) {
            let bytes_read = buffer.len();
            
            if bytes_read > 0 {
                batches.push(MemoryBatch {
                    region: MemoryRegion {
                        base_address: current_address,
                        size: bytes_read,
                        state: region.state,
                        protection: region.protection,
                        allocation_type: region.allocation_type,
                        is_executable: region.is_executable,
                        is_writable: region.is_writable,
                    },
                    data: buffer,
                    analysis: HashMap::new(),
                });

                current_address += bytes_read;
                remaining_size = remaining_size.saturating_sub(bytes_read);

                let progress = 1.0 - (remaining_size as f32 / total_size as f32);
                progress_callback(progress);
            } else {
                current_address += batch_size;
                remaining_size = remaining_size.saturating_sub(batch_size);
            }
        }
    }

    Ok(batches)
}

lazy_static! {
    static ref ANALYSIS_CACHE: std::sync::Mutex<std::collections::HashMap<u64, std::collections::HashMap<String, String>>> = 
        std::sync::Mutex::new(std::collections::HashMap::new());
}

#[derive(Debug, Clone)]
pub struct MemoryPattern {
    pub offset: usize,
    pub size: usize,
    pub matches: Vec<u8>,
}
