pub mod bridge;
pub mod java;
pub mod setup;

use crate::config::Config;
use crate::error::{GhidraError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct GhidraClient {
    install_dir: PathBuf,
    project_dir: PathBuf,
}

impl GhidraClient {
    pub fn new(config: Config) -> Result<Self> {
        let install_dir = config.get_ghidra_install_dir()?;
        let project_dir = config.get_project_dir()?;

        // Create project directory if it doesn't exist
        if !project_dir.exists() {
            std::fs::create_dir_all(&project_dir)?;
        }

        Ok(Self {
            install_dir,
            project_dir,
        })
    }

    pub fn verify_installation(&self) -> Result<()> {
        bridge::find_headless_script(&self.install_dir).map_err(|_| GhidraError::GhidraNotFound)?;
        Ok(())
    }

    pub fn get_project_path(&self, project_name: &str) -> PathBuf {
        self.project_dir.join(project_name)
    }

    pub fn project_exists(&self, project_name: &str) -> bool {
        ghidra_project_exists(&self.get_project_path(project_name))
    }

    pub fn create_project(&self, project_name: &str) -> Result<()> {
        let project_path = self.get_project_path(project_name);

        if self.project_exists(project_name) {
            return Ok(());
        }

        // Ghidra creates the project automatically when you import or process a file
        // Just create the directory structure
        std::fs::create_dir_all(&project_path)?;

        Ok(())
    }

    pub fn get_project_dir(&self) -> &Path {
        &self.project_dir
    }
}

/// Whether a Ghidra project exists at `project_path`.
///
/// `analyzeHeadless` materializes a project as sibling files
/// `<parent>/<basename>.gpr` (descriptor) + `<basename>.rep` (data dir), NOT
/// a `<parent>/<basename>` directory. A bare `create_dir` (see
/// `GhidraClient::create_project`) may leave an empty `<basename>` directory
/// without those artifacts, so the directory itself is not proof of existence.
pub fn ghidra_project_exists(project_path: &Path) -> bool {
    match (project_path.file_name(), project_path.parent()) {
        (Some(name), Some(parent)) => {
            let name = name.to_string_lossy();
            parent.join(format!("{}.gpr", name)).exists()
                || parent.join(format!("{}.rep", name)).exists()
        }
        _ => false,
    }
}

/// Whether a project contains persisted program data and can be opened with
/// `analyzeHeadless -process`.
///
/// A stale or newly-created empty project may have both `.gpr` and `.rep`
/// artifacts but only index files under `.rep/idata`. Starting a project-mode
/// bridge for that state fails before the bridge script can accept an import.
/// Real program data lives in bucket subdirectories under `idata`.
pub fn project_has_program_data(project_path: &Path) -> bool {
    let (Some(name), Some(parent)) = (project_path.file_name(), project_path.parent()) else {
        return false;
    };
    let name = name.to_string_lossy();
    let gpr = parent.join(format!("{}.gpr", name));
    let idata = parent.join(format!("{}.rep", name)).join("idata");

    gpr.is_file()
        && std::fs::read_dir(idata)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .any(|entry| entry.path().is_dir())
            })
            .unwrap_or(false)
}

/// Convenience wrapper: whether a Ghidra project exists at `project_path`.
pub fn project_exists(project_path: &Path) -> bool {
    ghidra_project_exists(project_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_client_creation() {
        // This will fail if GHIDRA_INSTALL_DIR is not set, which is expected
        let config = Config::default();
        let result = GhidraClient::new(config);

        // We can't test this properly without a Ghidra installation
        // Just verify the error is what we expect
        if let Err(e) = result {
            assert!(matches!(e, GhidraError::GhidraNotFound));
        }
    }
}
