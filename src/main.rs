mod core;

use std::collections::HashMap;
use std::time::Instant;
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use egui::{Color32, Ui};
use rfd::FileDialog;
use anyhow::Result;
use notify::{Watcher, RecommendedWatcher, Event};
use crossbeam_channel::Receiver as CrossbeamReceiver;
use crate::core::process::{ProcessAnalyzer, ProcessInfo};
use crate::core::memory::{MemoryRegion, MemoryAccess};
use eframe::CreationContext;
use windows::core::Error;
const ACCENT_COLOR: Color32 = Color32::from_rgb(0, 120, 215);
const WARNING_COLOR: Color32 = Color32::from_rgb(255, 140, 0);
const ERROR_COLOR: Color32 = Color32::from_rgb(255, 0, 0);
const SUCCESS_COLOR: Color32 = Color32::from_rgb(0, 255, 0);

#[derive(Default)]
pub struct Settings {
    highlight_suspicious: bool,
}

#[derive(Default, Clone, Debug)]
struct Theme {
    text: Color32,
    accent: Color32,
    background: Color32,
}

impl Theme {
    fn show_panel<R>(&self, ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
        egui::Frame::none()
            .fill(self.background)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, add_contents)
            .inner
    }
}

pub struct ThanatosApp {
    processes: Vec<ProcessInfo>,
    filtered_processes: Vec<ProcessInfo>,
    selected_process: Option<ProcessInfo>,
    process_filter: String,
    current_tab: String,
    memory_analysis: HashMap<usize, HashMap<String, String>>,
    analysis_receivers: Vec<(usize, mpsc::Receiver<(usize, HashMap<String, String>)>)>,
    analysis_progress: f32,
    selected_region: Option<MemoryRegion>,
    status_message: String,
    status_color: Color32,
    show_about: bool,
    show_system_processes: bool,
    search_text: String,
    memory_filter: String,
    memory_regions: Vec<MemoryRegion>,
    recent_dumps: Vec<PathBuf>,
    bookmarked_regions: Vec<usize>,
    hex_view_data: Option<Vec<u8>>,
    theme: Theme,
    settings: Settings,
    dump_watcher: Option<Box<dyn Watcher>>,
    dump_receiver: Option<CrossbeamReceiver<notify::Result<Event>>>,
    sort_by: String,
    sort_ascending: bool,
    last_analysis_time: Option<Instant>,
    message: Option<(String, Instant)>,
}
fn detect_strings(data: &[u8]) -> Option<Vec<String>> {
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
    
    if strings.is_empty() { None } else { Some(strings) }
}

fn has_code_patterns(data: &[u8]) -> bool {
    let patterns = [
        &[0x55, 0x48, 0x89, 0xe5][..], 
        &[0x48, 0x83, 0xec][..],       
        &[0xc3][..],                    
        &[0xe8][..],                    
        &[0xff, 0x25][..],             
    ];
    
    for window in data.windows(4) {
        if patterns.iter().any(|&pattern| window.starts_with(pattern)) {
            return true;
        }
    }
    false
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0u32; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &freq in &frequencies {
        if freq > 0 {
            let p = freq as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}
impl Default for ThanatosApp {
    fn default() -> Self {
        Self {
            processes: Vec::new(),
            filtered_processes: Vec::new(),
            selected_process: None,
            process_filter: String::new(),
            current_tab: "overview".to_string(),
            memory_analysis: HashMap::new(),
            analysis_receivers: Vec::new(),
            analysis_progress: 0.0,
            selected_region: None,
            status_message: String::new(),
            status_color: Color32::WHITE,
            show_about: false,
            show_system_processes: false,
            search_text: String::new(),
            memory_filter: String::new(),
            memory_regions: Vec::new(),
            recent_dumps: Vec::new(),
            bookmarked_regions: Vec::new(),
            hex_view_data: None,
            theme: Theme::default(),
            settings: Settings::default(),
            dump_watcher: None,
            dump_receiver: None,
            sort_by: "name".to_string(),
            sort_ascending: true,
            last_analysis_time: None,
            message: None,
        }
    }
}

impl ThanatosApp {
    pub fn new(cc: &CreationContext) -> Self {
        Self {
            processes: Vec::new(),
            filtered_processes: Vec::new(),
            selected_process: None,
            process_filter: String::new(),
            current_tab: "overview".to_string(),
            memory_analysis: HashMap::new(),
            analysis_receivers: Vec::new(),
            analysis_progress: 0.0,
            selected_region: None,
            status_message: String::new(),
            status_color: Color32::WHITE,
            show_about: false,
            show_system_processes: false,
            search_text: String::new(),
            memory_filter: String::new(),
            memory_regions: Vec::new(),
            recent_dumps: Vec::new(),
            bookmarked_regions: Vec::new(),
            hex_view_data: None,
            theme: Theme::default(),
            settings: Settings::default(),
            dump_watcher: None,
            dump_receiver: None,
            sort_by: "name".to_string(),
            sort_ascending: true,
            last_analysis_time: None,
            message: None,
        }
    }

    fn setup_dump_watcher<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(Box<dyn Watcher>, CrossbeamReceiver<notify::Result<Event>>)> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut watcher = RecommendedWatcher::new(
            move |res| { let _ = tx.send(res); },
            notify::Config::default()
        )?;
        watcher.watch(path.as_ref(), notify::RecursiveMode::NonRecursive)?;
        Ok((Box::new(watcher), rx))
    }

    fn select_process(&mut self, process_info: &ProcessInfo) {
        self.selected_process = Some(process_info.clone());
        self.memory_regions.clear();
        self.memory_analysis.clear();
        self.analysis_receivers.clear();
        
        if let Ok(analyzer) = ProcessAnalyzer::new(process_info.pid) {
            if let Ok(regions) = MemoryAccess::get_memory_map(process_info.pid) {
                self.memory_regions = regions;
            }
        }
    }

    fn filter_processes(&self) -> Vec<ProcessInfo> {
        let filter = self.process_filter.to_lowercase();
        self.processes.iter()
            .filter(|p| p.name.to_lowercase().contains(&filter))
            .cloned()
            .collect()
    }

    fn show_settings_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                
                ui.checkbox(&mut self.settings.highlight_suspicious, "Highlight suspicious regions");
                
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
                
                ui.group(|ui| {
                    ui.label("Dump Directory");
                    ui.horizontal(|ui| {
                        if ui.button("📂 Browse").clicked() {
                            if let Some(path) = FileDialog::new()
                                .set_title("Select dump directory")
                                .pick_folder() {
                                if let Ok((watcher, rx)) = self.setup_dump_watcher(path.as_path()) {
                                    self.dump_watcher = Some(watcher);
                                    self.dump_receiver = Some(rx);
                                }
                            }
                        }
                    });
                });
                
                ui.add_space(8.0);
                
                ui.horizontal(|ui| {
                    if ui.button("💾 Save").clicked() {
                    }
                    if ui.button("↺ Reset").clicked() {
                        self.settings = Settings::default();
                    }
                });
            });
    }

    fn configure_style(style: &mut egui::Style) {
        const BG_DARK: egui::Color32 = egui::Color32::from_rgb(18, 18, 18);
        const BG_MID: egui::Color32 = egui::Color32::from_rgb(28, 28, 28);
        const BG_LIGHT: egui::Color32 = egui::Color32::from_rgb(38, 38, 38);
        const FG_DIM: egui::Color32 = egui::Color32::from_rgb(120, 120, 120);
        const FG_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 220, 220);
        const ACCENT: egui::Color32 = egui::Color32::from_rgb(180, 180, 180);

        style.visuals.widgets.noninteractive.bg_fill = BG_MID;
        style.visuals.widgets.inactive.bg_fill = BG_LIGHT;
        style.visuals.widgets.hovered.bg_fill = ACCENT;
        style.visuals.widgets.active.bg_fill = FG_BRIGHT;
        style.visuals.widgets.open.bg_fill = BG_LIGHT;

        style.visuals.window_fill = BG_DARK;
        style.visuals.panel_fill = BG_MID;
        
        style.visuals.selection.bg_fill = ACCENT;
        style.visuals.selection.stroke.color = FG_BRIGHT;
        
        style.spacing.item_spacing = egui::vec2(6.0, 6.0);
        style.spacing.window_margin = egui::Margin::same(10.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
    }

    fn show_memory_viewer(&mut self, ui: &mut Ui, region: &MemoryRegion, process_id: u32) {
        const BG_DARK: egui::Color32 = egui::Color32::from_rgb(18, 18, 18);
        const FG_DIM: egui::Color32 = egui::Color32::from_rgb(120, 120, 120);
        const FG_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 220, 220);
        
        egui::Frame::none()
            .fill(BG_DARK)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading(egui::RichText::new(format!("0x{:X}", region.base_address))
                            .color(FG_BRIGHT));
                        ui.label(egui::RichText::new(format!("Size: {:.2} KB", region.size as f64 / 1024.0))
                            .color(FG_DIM));
                    });
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("⟳ Refresh").clicked() {
                            let region = region.clone();
                            self.selected_region = Some(region);
                        }
                        if ui.button("↓ Dump").clicked() {
                            if let Ok(path) = MemoryAccess::dump_region(process_id, region) {
                                self.show_message(format!("Dumped to {}", path.display()));
                            }
                        }
                        ui.label(egui::RichText::new(format!("{:?}", region.protection))
                            .color(FG_DIM));
                    });
                });
                
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);
                
                if let Ok(data) = MemoryAccess::read_memory(process_id, region.base_address, region.size.min(4096) as usize) {
                    self.show_hex_view(ui, &data);
                } else {
                    ui.colored_label(FG_DIM, "Memory access failed");
                }
            });
    }

    fn show_hex_view(&mut self, ui: &mut Ui, data: &[u8]) {
        const BYTES_PER_ROW: usize = 16;
        const FG_DIM: egui::Color32 = egui::Color32::from_rgb(120, 120, 120);
        const FG_MID: egui::Color32 = egui::Color32::from_rgb(170, 170, 170);
        const FG_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 220, 220);
        
        egui::ScrollArea::vertical()
            .max_height(400.0)
            .show(ui, |ui| {
                let mut offset = 0;
                for chunk in data.chunks(BYTES_PER_ROW) {
                    let row = ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(format!("{:08X}", offset))
                            .monospace()
                            .color(FG_DIM));
                        
                        ui.add_space(16.0);
                        
                        let hex_text = chunk.iter()
                            .enumerate()
                            .map(|(i, &b)| {
                                if i == BYTES_PER_ROW / 2 {
                                    format!(" {:02X}", b)
                                } else {
                                    format!("{:02X}", b)
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(" ");
                        
                        ui.label(egui::RichText::new(hex_text)
                            .monospace()
                            .color(FG_BRIGHT));
                        
                        ui.add_space(16.0);
                        
                        let ascii_text = chunk.iter()
                            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                            .collect::<String>();
                        
                        ui.label(egui::RichText::new(ascii_text)
                            .monospace()
                            .color(FG_MID));
                    });
                    
                    if offset % (BYTES_PER_ROW * 4) == 0 {
                        ui.add_space(4.0);
                    }
                    
                    offset += BYTES_PER_ROW;
                }
            });
    }

    fn show_memory_analysis(&mut self, ui: &mut Ui) {
        const BG_DARK: egui::Color32 = egui::Color32::from_rgb(18, 18, 18);
        const FG_DIM: egui::Color32 = egui::Color32::from_rgb(120, 120, 120);
        const FG_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 220, 220);
        const SUSPICIOUS_COLOR: egui::Color32 = egui::Color32::from_rgb(255, 140, 0);
        
        let analysis_data: Vec<(usize, HashMap<String, String>)> = self.memory_analysis
            .iter()
            .map(|(&addr, findings)| (addr, findings.clone()))
            .collect();
        
        egui::Frame::none()
            .fill(BG_DARK)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Memory Analysis");
                    
                    if !self.analysis_receivers.is_empty() {
                        ui.spinner();
                    }
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("🔍 Analyze").clicked() && self.selected_process.is_some() {
                            self.start_memory_analysis();
                        }
                    });
                });
                
                if !self.analysis_receivers.is_empty() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let progress = self.analysis_progress * 100.0;
                        ui.add(egui::ProgressBar::new(self.analysis_progress)
                            .text(format!("Analyzing... {:.0}%", progress)));
                    });
                }
    
                ui.add_space(8.0);
                
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        if analysis_data.is_empty() && self.analysis_receivers.is_empty() {
                            ui.label(egui::RichText::new("No analysis results. Click 'Analyze' to start.")
                                .color(FG_DIM));
                            return;
                        }
    
                        for (address, findings) in analysis_data {
                            let is_suspicious = findings.values()
                                .any(|v| v.contains("suspicious") || v.contains("unusual"));
                            
                            egui::Frame::none()
                                .fill(if is_suspicious && self.settings.highlight_suspicious {
                                    SUSPICIOUS_COLOR.linear_multiply(0.2)
                                } else {
                                    ui.visuals().extreme_bg_color
                                })
                                .rounding(egui::Rounding::same(4.0))
                                .show(ui, |ui| {
                                    ui.collapsing(format!("Region: 0x{:X}", address), |ui| {

                                        if let Some(hex_data) = findings.get("hex_data") {
                                            if let Ok(data) = base64::decode(hex_data) {
                                                ui.group(|ui| {
                                                    ui.label("Memory Preview:");
                                                    self.show_hex_view(ui, &data);
                                                });
                                                ui.add_space(4.0);
                                            }
                                        }
                                        

                                        for (key, value) in findings {
                                            if key != "hex_data" {
                                                ui.horizontal(|ui| {
                                                    ui.label(egui::RichText::new(&key)
                                                        .color(FG_DIM));
                                                    ui.label(egui::RichText::new(&value)
                                                        .color(FG_BRIGHT));
                                                });
                                            }
                                        }
                                    });
                                });
                            ui.add_space(4.0);
                        }
                    });
            });
    }
    fn start_memory_analysis(&mut self) {
        if let Some(process) = &self.selected_process {
            self.memory_analysis.clear();
            self.analysis_receivers.clear();
            self.analysis_progress = 0.0;
            

            let regions: Vec<_> = self.memory_regions.iter()
                .filter(|r| r.size > 0 && r.size <= (1024 * 1024 * 32)) 
                .cloned()
                .collect();
                    
            let total_regions = regions.len();
            println!("Starting analysis of {} memory regions", total_regions);
            

            for chunk in regions.chunks(10) {
                for region in chunk {
                    let (tx, rx) = mpsc::channel();
                    let pid = process.pid;
                    let region = region.clone();
                    
                    std::thread::spawn(move || {
                        let mut findings = HashMap::new();
                        
                        let chunk_size = region.size.min(4096) as usize;
                        if let Ok(data) = MemoryAccess::read_memory(pid, region.base_address, chunk_size) {
                            findings.insert("hex_data".to_string(), 
                                base64::encode(&data[..chunk_size.min(256)]));
                            
                            if let Some(strings) = detect_strings(&data) {
                                if !strings.is_empty() {
                                    findings.insert("Strings".to_string(), 
                                        format!("Found {} interesting strings", strings.len()));
                                    let preview: Vec<_> = strings.iter()
                                        .take(3)
                                        .cloned()
                                        .collect();
                                    findings.insert("string_preview".to_string(), 
                                        preview.join(", "));
                                }
                            }
                            
                            if has_code_patterns(&data) {
                                findings.insert("Code".to_string(), 
                                    "Contains executable code patterns".to_string());
                            }
                            
                            let entropy = calculate_entropy(&data);
                            if entropy > 6.5 {
                                findings.insert("Entropy".to_string(), 
                                    format!("High entropy ({:.2}) - possible encryption/compression", entropy));
                            }
                            
                            let protection = format!("{:?}", region.protection);
                            if protection.contains("EXECUTE") && protection.contains("WRITE") {
                                findings.insert("Protection".to_string(), 
                                    "Suspicious RWX permissions (possible shellcode)".to_string());
                            }
                            
                            let size_mb = region.size as f64 / (1024.0 * 1024.0);
                            if size_mb >= 1.0 {
                                findings.insert("Size".to_string(), 
                                    format!("Large region ({:.2} MB)", size_mb));
                            }
                            
                            if region.base_address < 0x10000 {
                                findings.insert("Address".to_string(),
                                    "Suspicious low memory address".to_string());
                            }
                        }
                        
                        if !findings.is_empty() {
                            tx.send((region.base_address, findings)).ok();
                        }
                    });
                    
                    self.analysis_receivers.push((region.base_address, rx));
                }
                
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            
            self.last_analysis_time = Some(Instant::now());
            println!("Analysis started with {} receivers", self.analysis_receivers.len());
        }
    }

    fn show_status(&mut self, message: &str, color: egui::Color32) {
        self.status_message = message.to_string();
        self.status_color = color;
    }

    fn refresh_processes(&mut self) {
        match ProcessAnalyzer::get_running_processes() {
            Ok(mut processes) => {
                if !self.show_system_processes {
                    processes.retain(|p| p.pid > 4); 
                }
                println!("Found {} processes", processes.len());
                self.processes = processes;
                if let Some(ref pid) = self.selected_process {
                    if !self.processes.iter().any(|p| p.pid == pid.pid) {
                        self.selected_process = None;
                    }
                }
            }
            Err(e) => {
                println!("Failed to get processes: {}", e);
                self.show_status(&format!("Failed to get processes: {}", e), ERROR_COLOR);
            }
        }
    }

    fn sort_processes(&self) -> Vec<ProcessInfo> {
        let mut processes = self.processes.clone();
        processes.sort_by(|a, b| {
            match self.sort_by.as_str() {
                "name" => {
                    if self.sort_ascending { a.name.cmp(&b.name) } else { b.name.cmp(&a.name) }
                }
                "pid" => {
                    if self.sort_ascending { a.pid.cmp(&b.pid) } else { b.pid.cmp(&a.pid) }
                }
                "memory" => {
                    if self.sort_ascending { a.memory_usage.cmp(&b.memory_usage) } else { b.memory_usage.cmp(&a.memory_usage) }
                }
                "priority" => {
                    if self.sort_ascending { a.priority.cmp(&b.priority) } else { b.priority.cmp(&a.priority) }
                }
                _ => std::cmp::Ordering::Equal,
            }
        });
        processes
    }

    fn refresh_memory_regions(&mut self) {
        if let Some(process) = &self.selected_process {
            if let Ok(regions) = MemoryAccess::get_memory_map(process.pid) {
                self.memory_regions = regions;
            }
        }
    }

    fn show_process_list(&mut self, ui: &mut Ui) {
        
        let should_refresh = ui.button("⟳ Refresh").clicked();
        
        
        let mut search_text = self.search_text.clone();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔍").size(16.0));
            let search_changed = ui.text_edit_singleline(&mut search_text).changed();
            if search_changed {
                self.search_text = search_text.clone();
                self.refresh_processes();
            }
        });
    
        
        let mut show_system = self.show_system_processes;
        let system_changed = ui.checkbox(&mut show_system, "Show System Processes").changed();
        if system_changed {
            self.show_system_processes = show_system;
            self.refresh_processes();
        }
    
        if should_refresh {
            self.refresh_processes();
        }
    
        
        let filtered_processes: Vec<_> = self.processes.iter()
            .filter(|p| {
                if self.search_text.is_empty() {
                    true
                } else {
                    p.name.to_lowercase().contains(&self.search_text.to_lowercase()) ||
                    p.pid.to_string().contains(&self.search_text)
                }
            })
            .map(|p| (p.pid, p.name.clone(), p.memory_usage))
            .collect();
    
        
        let mut clicked_process: Option<(u32, String, u64)> = None;
    
        
        self.theme.show_panel(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("Processes").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled_ui(false, |ui| {
                        ui.button("⟳ Refresh");
                    });
                });
            });
    
            ui.add_space(8.0);
    
            
            egui::Frame::none()
                .fill(ui.visuals().faint_bg_color)
                .rounding(egui::Rounding::same(4.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("🔍").size(16.0));
                        let mut dummy_text = self.search_text.clone();
                        ui.add_enabled_ui(false, |ui| {
                            ui.text_edit_singleline(&mut dummy_text);
                        });
                    });
                    ui.add_enabled_ui(false, |ui| {
                        ui.checkbox(&mut self.show_system_processes, "Show System Processes");
                    });
                });
    
            ui.add_space(8.0);
    
            
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    if filtered_processes.is_empty() {
                        ui.label("No processes found");
                    } else {
                        for &(pid, ref name, memory) in &filtered_processes {
                            let is_selected = self.selected_process
                                .as_ref()
                                .map_or(false, |p| p.pid == pid);
    
                            egui::Frame::none()
                                .fill(if is_selected {
                                    egui::Color32::from_rgb(45, 80, 125)
                                } else {
                                    ui.visuals().extreme_bg_color
                                })
                                .rounding(egui::Rounding::same(4.0))
                                .show(ui, |ui| {
                                    if ui.add(egui::SelectableLabel::new(
                                        is_selected,
                                        egui::RichText::new(format!("{}\nPID: {} | Memory: {:.1} MB",
                                            name,
                                            pid,
                                            memory as f64 / (1024.0 * 1024.0)
                                        ))
                                        .color(if is_selected {
                                            egui::Color32::WHITE
                                        } else {
                                            egui::Color32::LIGHT_GRAY
                                        })
                                    )).clicked() {
                                        clicked_process = Some((pid, name.clone(), memory));
                                    }
                                });
                            ui.add_space(2.0);
                        }
                    }
                });
        });
    
        
        if let Some((pid, name, memory)) = clicked_process {
            self.selected_process = Some(ProcessInfo {
                path: String::new(),
                pid,
                name,
                memory_usage: memory,
                priority: 0,
            });
            self.refresh_memory_regions();
        }
    }

    fn show_statistics(&mut self, ui: &mut Ui, process: &ProcessInfo) {
        ui.heading("Process Statistics");
        
        
        ui.group(|ui| {
            ui.label(format!("Process Name: {}", process.name));
            ui.label(format!("Process ID: {}", process.pid));
            ui.label(format!("Memory Usage: {} MB", process.memory_usage / (1024 * 1024)));
            if let Some(time) = &self.last_analysis_time {
                ui.label(format!("Last Analysis: {}", time.elapsed().as_secs()));
            }
        });
    
        
        if !self.memory_regions.is_empty() {
            ui.add_space(10.0);
            ui.heading("Memory Statistics");
            ui.group(|ui| {
                let total_regions = self.memory_regions.len();
                let executable_regions = self.memory_regions.iter()
                    .filter(|r| r.is_executable)
                    .count();
                let writable_regions = self.memory_regions.iter()
                    .filter(|r| r.is_writable)
                    .count();
                let total_memory: usize = self.memory_regions.iter()
                    .map(|r| r.size)
                    .sum();
    
                ui.label(format!("Total Memory Regions: {}", total_regions));
                ui.label(format!("Executable Regions: {}", executable_regions));
                ui.label(format!("Writable Regions: {}", writable_regions));
                ui.label(format!("Total Memory Mapped: {} MB", total_memory / (1024 * 1024)));
            });
        }
    
        
        if !self.memory_analysis.is_empty() {
            ui.add_space(10.0);
            ui.heading("Analysis Results");
            ui.group(|ui| {
                let analyzed_regions = self.memory_analysis.len();
                let suspicious_regions = self.memory_analysis.values()
                    .filter(|analysis| analysis.values().any(|v| v.contains("suspicious")))
                    .count();
    
                ui.label(format!("Analyzed Regions: {}", analyzed_regions));
                ui.label(format!("Suspicious Regions: {}", suspicious_regions));
            });
        }
    
        
        if !self.recent_dumps.is_empty() {
            ui.add_space(10.0);
            ui.heading("Recent Activity");
            ui.group(|ui| {
                ui.label(format!("Recent Memory Dumps: {}", self.recent_dumps.len()));
                if !self.bookmarked_regions.is_empty() {
                    ui.label(format!("Bookmarked Regions: {}", self.bookmarked_regions.len()));
                }
            });
        }
    }

    fn show_memory_map(&mut self, ui: &mut egui::Ui, pid: u32) {
        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.text_edit_singleline(&mut self.memory_filter);
            
            if ui.button("⟳ Refresh").clicked() {
                if let Ok(regions) = MemoryAccess::get_memory_map(pid) {
                    self.memory_regions = regions;
                }
            }
        });
    
        ui.add_space(8.0);
    
        let mut selected_address = None;
    
        egui::ScrollArea::vertical()
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Address");
                    ui.add_space(80.0);
                    ui.label("Size");
                    ui.add_space(60.0);
                    ui.label("Protection");
                    ui.add_space(60.0);
                    ui.label("Type");
                });
                
                ui.separator();
    
                let filter = self.memory_filter.to_lowercase();
                let filtered_regions: Vec<_> = self.memory_regions.iter()
                    .filter(|region| {
                        format!("{:X}", region.base_address).to_lowercase().contains(&filter)
                            || format!("{:?}", region.protection).to_lowercase().contains(&filter)
                    })
                    .collect();
    
                for region in &filtered_regions {
                    let is_selected = self.selected_region.as_ref()
                        .map_or(false, |r| r.base_address == region.base_address);
                    
                    let row = ui.horizontal(|ui| {
                        let protection_str = format!("{:?}", region.protection);
                        let region_type = match region.allocation_type {
                            windows::Win32::System::Memory::MEM_PRIVATE => "Private",
                            windows::Win32::System::Memory::MEM_MAPPED => "Mapped",
                            _ => "Other"
                        };
    
                        let text = format!(
                            "0x{:X}    {:>8} KB    {:<12}    {}",
                            region.base_address,
                            region.size / 1024,
                            protection_str,
                            region_type
                        );
                        
                        let response = ui.selectable_label(is_selected, text);
                        
                        if protection_str.contains("EXECUTE") {
                            ui.colored_label(WARNING_COLOR, "⚡");
                        }
                        
                        response
                    });
    
                    if row.inner.clicked() {
                        selected_address = Some(region.base_address);
                        
                        if let Ok(data) = MemoryAccess::read_memory(pid, region.base_address, region.size.min(4096) as usize) {
                            self.hex_view_data = Some(data);
                        }
                    }
    
                    if is_selected {
                        ui.add_space(4.0);
                        if let Some(data) = &self.hex_view_data {
                            self.render_memory_view(ui, data);
                        }
                    }
                }
            });
    
        
        if let Some(addr) = selected_address {
            if let Some(region) = self.memory_regions.iter().find(|r| r.base_address == addr) {
                self.selected_region = Some(region.clone());
            }
        }
    }
    
    fn render_memory_view(&self, ui: &mut egui::Ui, data: &[u8]) {
        ui.group(|ui| {
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    
                    for (i, chunk) in data.chunks(16).enumerate() {
                        let hex = chunk.iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        
                        let ascii = chunk.iter()
                            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                            .collect::<String>();
                        
                        ui.monospace(format!("{:08X}: {:48} {}", i * 16, hex, ascii));
                    }
                });
        });
    }

    fn show_process_info(&mut self, ui: &mut Ui, process: &ProcessInfo) {
        ui.heading("Process Information");
        ui.add_space(8.0);
        
        egui::Grid::new("process_info_grid")
            .num_columns(2)
            .spacing([40.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name:");
                ui.label(&process.name);
                ui.end_row();
                
                ui.label("PID:");
                ui.label(process.pid.to_string());
                ui.end_row();
                
                ui.label("Memory Usage:");
                ui.label(format!("{:.1} MB", process.memory_usage as f64 / (1024.0 * 1024.0)));
                ui.end_row();
                
                ui.label("Priority:");
                ui.label(process.priority.to_string());
                ui.end_row();
            });
    }

    fn show_threads(&mut self, ui: &mut Ui, process_id: u32) {
        if let Ok(threads) = ProcessAnalyzer::get_threads(process_id) {
            ui.heading("Threads");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for thread in threads {
                        ui.horizontal(|ui| {
                            ui.label(format!("TID: {}", thread.id));
                            ui.separator();
                            ui.label(format!("Priority: {}", thread.priority));

                        });
                    }
                });
        } else {
            ui.label("Failed to get thread information");
        }
    }

    fn show_modules(&mut self, ui: &mut Ui, process_id: u32) {
        if let Ok(modules) = ProcessAnalyzer::get_modules(process_id) {
            ui.heading("Modules");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for module in modules {
                        egui::Frame::none()
                            .fill(ui.visuals().extreme_bg_color)
                            .rounding(egui::Rounding::same(4.0))
                            .show(ui, |ui| {
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new(&module.name).strong());
                                    ui.label(format!("Name: {}", module.name));                                    ui.horizontal(|ui| {
                                        ui.label(format!("Base: 0x{:X}", module.base_address));
                                        ui.separator();
                                        ui.label(format!("Size: {:.2} MB", module.size as f64 / (1024.0 * 1024.0)));
                                    });
                                });
                            });
                        ui.add_space(2.0);
                    }
                });
        } else {
            ui.label("Failed to get module information");
        }
    }

    fn show_processes(&mut self, ui: &mut Ui) {
        if let Ok(mut processes) = ProcessAnalyzer::get_running_processes() {
            
            processes.retain(|p| p.pid > 4);  
            self.processes = processes;
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                for process in self.processes.clone() {
                    ui.horizontal(|ui| {
                        if ui.button("🔍").clicked() {
                            self.selected_process = Some(ProcessInfo {
                                path: process.path.clone(), 
                                pid: process.pid,
                                name: process.name.clone(),
                                memory_usage: process.memory_usage,
                                priority: process.priority,
                            });
                            self.refresh_memory_regions();
                        }
                        
                        ui.monospace(format!(
                            "{:<8} {:<20} {:>10} KB",
                            process.pid,
                            process.name,
                            process.memory_usage / 1024
                        ));
                    });
                }
            });
        } else {
            ui.label("Failed to get process list");
        }
    }

    fn update_ui(&mut self, ctx: &egui::Context) {
        
        if let Some((msg, time)) = &self.message {
            if time.elapsed().as_secs() < 3 {
                egui::Window::new("Message")
                    .anchor(egui::Align2::CENTER_BOTTOM, egui::Vec2::new(0.0, -30.0))
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(msg);
                    });
            } else {
                self.message = None;
            }
        }
    }
    fn update_analysis(&mut self, ctx: &egui::Context) {
        if self.analysis_receivers.is_empty() {
            return;
        }
    
        let total = self.analysis_receivers.len();
        let mut completed = 0;
    
        
        self.analysis_receivers.retain(|(addr, rx)| {
            match rx.try_recv() {
                Ok((addr, findings)) => {
                    self.memory_analysis.insert(addr, findings);
                    completed += 1;
                    false 
                }
                Err(TryRecvError::Empty) => true, 
                Err(TryRecvError::Disconnected) => {
                    completed += 1;
                    false 
                }
            }
        });
    
        
        self.analysis_progress = completed as f32 / total as f32;
    
        
        if !self.analysis_receivers.is_empty() {
            ctx.request_repaint();
        }
    }
    fn update_analysis_state(&mut self) {
        let total = self.analysis_receivers.len();
        if total == 0 {
            return;
        }
    
        let initial_count = self.analysis_receivers.len();
        let mut i = 0;
        
        while i < self.analysis_receivers.len() {
            match self.analysis_receivers[i].1.try_recv() {
                Ok((address, findings)) => {
                    println!("Received analysis for region 0x{:X}", address);
                    self.memory_analysis.insert(address, findings);
                    self.analysis_receivers.remove(i);
                }
                Err(TryRecvError::Empty) => {
                    i += 1;
                }
                Err(TryRecvError::Disconnected) => {
                    println!("Receiver disconnected for region {}", i);
                    self.analysis_receivers.remove(i);
                }
            }
        }
    
        let completed = initial_count - self.analysis_receivers.len();
        self.analysis_progress = completed as f32 / initial_count as f32;
        
        if self.analysis_receivers.is_empty() {
            println!("Analysis completed with {} results", self.memory_analysis.len());
        }
    }
    fn update_analysis_results(&mut self) {
        let mut completed = Vec::new();
        let mut i = 0;
        while i < self.analysis_receivers.len() {
            let (_base_address, rx) = &self.analysis_receivers[i];
            match rx.try_recv() {
                Ok((addr, results)) => {
                    self.memory_analysis.insert(addr, results);
                    completed.push(i);
                }
                Err(TryRecvError::Empty) => {
                    
                },
                Err(TryRecvError::Disconnected) => {
                    completed.push(i);
                }
            }
            i += 1;
        }
        
        
        for i in completed.into_iter().rev() {
            self.analysis_receivers.remove(i);
        }
    }

    fn quick_analyze_region(&mut self, region: &MemoryRegion) {
        let _process_id = if let Some(process) = &self.selected_process {
            process.pid
        } else {
            return;
        };

        if let Some(_analysis) = self.memory_analysis.get(&region.base_address) {
            
            return;
        }

        self.analyze_memory(region);
    }

    fn analyze_memory(&mut self, region: &MemoryRegion) {
        let process_id = if let Some(process) = &self.selected_process {
            process.pid
        } else {
            return;
        };

        
        self.memory_analysis.remove(&region.base_address);
        
        
        self.analysis_receivers.retain(|(addr, _)| *addr != region.base_address);

        let (tx, rx) = mpsc::channel();
        let base_address = region.base_address;
        let region = region.clone();

        std::thread::spawn(move || {
            if let Ok(process) = ProcessAnalyzer::new(process_id) {
                if let Ok(analysis) = process.analyze_region(&region) {
                    let _ = tx.send((base_address, analysis));
                }
            }
        });

        self.analysis_receivers.push((base_address, rx));
        self.show_message(format!("Started analysis of region at 0x{:X}", base_address));
    }

    fn show_message(&mut self, msg: String) {
        self.message = Some((msg, Instant::now()));
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        
        self.update_analysis_state();
        if !self.analysis_receivers.is_empty() {
            ctx.request_repaint();
        }
        if let Some((msg, time)) = &self.message {
            if time.elapsed().as_secs() < 3 {
                egui::Window::new("Message")
                    .anchor(egui::Align2::CENTER_BOTTOM, egui::Vec2::new(0.0, -30.0))
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(msg);
                    });
            } else {
                self.message = None;
            }
        }

        let mut style = (*ctx.style()).clone();
        Self::configure_style(&mut style);
        ctx.set_style(style);

        self.update_ui(ctx);
        if self.processes.is_empty() {
            self.refresh_processes();
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Exit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh_processes();
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
            });
        });

        egui::SidePanel::left("process_list")
            .resizable(true)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.heading("Processes");
                    ui.add_space(4.0);
                    
                    
                    ui.horizontal(|ui| {
                        let search = ui.text_edit_singleline(&mut self.process_filter);
                        if search.changed() {
                            self.filter_processes();
                        }
                    });
                    
                    ui.add_space(8.0);
                    
                    egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        let processes: Vec<_> = self.processes.iter().cloned().collect();
                        for process in processes {
                            let is_selected = self.selected_process
                                .as_ref()
                                .map_or(false, |p| p.pid == process.pid);
                            
                            let response = ui.selectable_label(
                                is_selected,
                                format!("{} ({})", process.name, process.pid)
                            );
                            
                            if response.clicked() {
                                self.select_process(&process);
                            }
                        }
                    });
                });
            });

            if let Some(process) = &self.selected_process {
                let process_clone = process.clone();
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::TopBottomPanel::top("process_tabs").show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            for tab in ["Overview", "Memory", "Analysis", "Statistics"] {
                                let selected = self.current_tab.eq_ignore_ascii_case(tab);
                                if ui.selectable_label(selected, tab).clicked() {
                                    self.current_tab = tab.to_lowercase();
                                }
                            }
                        });
                    });
            
                    match self.current_tab.as_str() {
                        "overview" => self.show_process_info(ui, &process_clone),
                        "memory" => self.show_memory_map(ui, process_clone.pid),
                        "analysis" => self.show_memory_analysis(ui),
                        "statistics" => self.show_statistics(ui, &process_clone),
                        _ => {}
                    }
                });

        } else {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.label(egui::RichText::new("Select a process to begin")
                        .size(24.0)
                        .color(egui::Color32::from_rgb(120, 120, 120)));
                });
            });
        }

        if !self.status_message.is_empty() {
            egui::TopBottomPanel::bottom("status")
                .min_height(30.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&self.status_message)
                            .color(self.status_color));
                    });
                });
        }
    }
}

impl eframe::App for ThanatosApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        
        self.update_analysis(ctx);  

        if let Some((msg, time)) = &self.message {
            if time.elapsed().as_secs() < 3 {
                egui::Window::new("Message")
                    .anchor(egui::Align2::CENTER_BOTTOM, egui::Vec2::new(0.0, -30.0))
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(msg);
                    });
            } else {
                self.message = None;
            }
        }

        let mut style = (*ctx.style()).clone();
        Self::configure_style(&mut style);
        ctx.set_style(style);

        self.update_ui(ctx);
        if self.processes.is_empty() {
            self.refresh_processes();
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Exit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh_processes();
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
            });
        });

        egui::SidePanel::left("process_list")
            .resizable(true)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.heading("Processes");
                    ui.add_space(4.0);
                    
                    
                    ui.horizontal(|ui| {
                        let search = ui.text_edit_singleline(&mut self.process_filter);
                        if search.changed() {
                            self.filter_processes();
                        }
                    });
                    
                    ui.add_space(8.0);
                    
                    egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        let to_select = {
                            let mut selected = None;
                            for process in self.processes.iter() {
                                let is_selected = self.selected_process
                                    .as_ref()
                                    .map_or(false, |p| p.pid == process.pid);
                                
                                let response = ui.selectable_label(
                                    is_selected,
                                    format!("{} ({})", process.name, process.pid)
                                );
                                
                                if response.clicked() {
                                    selected = Some(process.clone());
                                }
                            }
                            selected
                        };
                        
                        if let Some(process) = to_select {
                            self.select_process(&process);
                        }
                    });
                });
            });

        if let Some(process) = &self.selected_process {
            let process = process.clone(); 
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::TopBottomPanel::top("process_tabs").show_inside(ui, |ui| {
                    ui.horizontal(|ui| {
                        for tab in ["Overview", "Memory", "Analysis", "Statistics"] {
                            let selected = self.current_tab.eq_ignore_ascii_case(tab);
                            if ui.selectable_label(selected, tab).clicked() {
                                self.current_tab = tab.to_lowercase();
                            }
                        }
                    });
                });

                ui.add_space(8.0);

                match self.current_tab.as_str() {
                    "overview" => self.show_process_info(ui, &process),
                    "memory" => self.show_memory_map(ui, process.pid),
                    "analysis" => self.show_memory_analysis(ui),
                    "statistics" => self.show_statistics(ui, &process),
                    _ => {}
                }
            });
        } else {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.label(egui::RichText::new("Select a process to begin")
                        .size(24.0)
                        .color(egui::Color32::from_rgb(120, 120, 120)));
                });
            });
        }

        if !self.status_message.is_empty() {
            egui::TopBottomPanel::bottom("status")
                .min_height(30.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&self.status_message)
                            .color(self.status_color));
                    });
                });
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 720.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Thanatos",
        options,
        Box::new(|cc| Box::new(ThanatosApp::new(cc)))
    )
}
