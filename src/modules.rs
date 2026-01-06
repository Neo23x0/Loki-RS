pub mod process_check;
pub mod filesystem_scan;

use yara_x::Rules;
use std::sync::Arc;
use crate::{ScanConfig, HashIOCCollections, FalsePositiveHashCollections, FilenameIOC, C2IOC};
use crate::helpers::jsonl_logger::JsonlLogger;
use crate::helpers::remote_logger::RemoteLogger;
use crate::helpers::interrupt::ScanState;

pub struct ScanContext<'a> {
    pub compiled_rules: &'a Rules,
    pub scan_config: &'a ScanConfig,
    pub hash_collections: &'a HashIOCCollections,
    pub fp_hash_collections: &'a FalsePositiveHashCollections,
    pub filename_iocs: &'a Vec<FilenameIOC>,
    pub c2_iocs: &'a [C2IOC],
    pub jsonl_logger: Option<&'a JsonlLogger>,
    pub remote_logger: Option<&'a RemoteLogger>,
    pub scan_state: Option<Arc<ScanState>>,
    pub target_folder: &'a str,
}

pub type ModuleResult = (usize, usize, usize, usize, usize);

pub trait ScanModule {
    fn name(&self) -> &'static str;
    fn run(&self, context: &ScanContext) -> ModuleResult;
}
