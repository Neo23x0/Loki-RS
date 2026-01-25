pub mod process_check;
pub mod filesystem_scan;

use regex::Regex;
use yara_x::Rules;
use std::sync::Arc;
use crate::{ScanConfig, HashIOCCollections, FalsePositiveHashCollections, FilenameIOC, C2IOC};
use crate::helpers::unified_logger::UnifiedLogger;
use crate::helpers::interrupt::ScanState;

pub struct ScanContext<'a> {
    pub compiled_rules: &'a Rules,
    pub scan_config: &'a ScanConfig,
    pub hash_collections: &'a HashIOCCollections,
    pub fp_hash_collections: &'a FalsePositiveHashCollections,
    pub filename_iocs: &'a Vec<FilenameIOC>,
    pub c2_iocs: &'a [C2IOC],
    pub exclusion_patterns: &'a Vec<Regex>,
    pub logger: &'a UnifiedLogger,
    pub scan_state: Option<Arc<ScanState>>,
    pub target_folder: &'a str,
}

pub type ModuleResult = (usize, usize, usize, usize, usize);

pub trait ScanModule {
    fn name(&self) -> &'static str;
    fn run(&self, context: &ScanContext) -> ModuleResult;
}
