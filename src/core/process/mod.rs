use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::Win32::System::Threading::{
    SetPriorityClass, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
    PROCESS_CREATION_FLAGS, OpenProcess
};
use crate::core::memory::MemoryRegion;
use anyhow::{Result, anyhow};
use windows::core::Error;
use std::collections::HashMap;
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX, K32EnumProcesses
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD, Module32FirstW, Module32NextW,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32
};
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub memory_usage: u64,
    pub priority: u32,
}

pub struct ProcessAnalyzer {
    handle: HANDLE,
    pub id: u32,
}

#[derive(Debug)]
pub struct ThreadInfo {
    pub id: u32,
    pub priority: i32,
}

#[derive(Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct ProcessMemoryInfo {
    pub memory_usage: u64,
}

impl ProcessAnalyzer {
    pub fn new(pid: u32) -> Result<Self> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
                false,
                pid
            )?;

            if handle.is_invalid() {
                return Err(anyhow!("Failed to open process"));
            }

            Ok(ProcessAnalyzer {
                handle,
                id: pid,
            })
        }
    }

    pub fn analyze_region(&self, _region: &MemoryRegion) -> Result<HashMap<String, String>> {
        let analysis = HashMap::new();
        Ok(analysis)
    }

    pub fn get_memory_info(&self) -> Result<ProcessMemoryInfo> {
        let mut pmc = PROCESS_MEMORY_COUNTERS_EX::default();
        
        unsafe {
            GetProcessMemoryInfo(
                self.handle,
                &mut pmc as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            )?;  
        }
    
        Ok(ProcessMemoryInfo {
            memory_usage: pmc.WorkingSetSize as u64,
        })
    }
    
    pub fn set_priority(&self, priority: u32) -> Result<()> {
        unsafe {
            SetPriorityClass(
                self.handle,
                PROCESS_CREATION_FLAGS(priority)
            )?;  
        }
        Ok(())
    }
    pub fn get_running_processes() -> Result<Vec<ProcessInfo>> {
        unsafe {          
            let mut processes = Vec::with_capacity(1024);
            let mut bytes_returned = 0;
                
            let mut buffer = vec![0u32; 1024];
            if !K32EnumProcesses(
                buffer.as_mut_ptr(),
                (buffer.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned
            ).as_bool() {
                return Err(Error::from_win32().into());
            }
        
            let count = bytes_returned as usize / std::mem::size_of::<u32>();
                
            for pid in buffer[..count].iter() {
                if let Ok(analyzer) = ProcessAnalyzer::new(*pid) {
                    let mut name_buf = vec![0u16; 260];
                    if GetProcessImageFileNameW(
                        analyzer.handle,
                        &mut name_buf
                    ) > 0 {
                        let name = String::from_utf16_lossy(&name_buf)
                            .trim_matches(char::from(0))
                            .to_string();
                            
                        if let Ok(memory_info) = analyzer.get_memory_info() {
                            processes.push(ProcessInfo {
                                pid: *pid,
                                name: name.clone(),
                                path: name,
                                memory_usage: memory_info.memory_usage,
                                priority: 0,
                            });
                        }
                    }
                }
            }
            
            Ok(processes)
        }
    }
    
    pub fn get_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
            let mut threads = Vec::new();
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
    
            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        threads.push(ThreadInfo {
                            id: entry.th32ThreadID,
                            priority: entry.tpBasePri,
                        });
                    }
                    
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
    
            CloseHandle(snapshot);
            Ok(threads)
        }
    }
    
    pub fn get_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid
            )?;
            
            let mut modules = Vec::new();
            let mut entry = MODULEENTRY32W {
                dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };
    
            if Module32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szModule)
                        .trim_matches(char::from(0))
                        .to_string();
                    
                    modules.push(ModuleInfo {
                        name,
                        base_address: entry.modBaseAddr as usize,
                        size: entry.modBaseSize as usize,
                    });
                    
                    if Module32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
    
            CloseHandle(snapshot);
            Ok(modules)
        }
    }
}

impl Drop for ProcessAnalyzer {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}