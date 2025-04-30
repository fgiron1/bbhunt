use std::collections::HashMap;
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use dialoguer::{theme::ColorfulTheme, Input, Confirm};
use serde_json::Value;

use crate::core::report::{Report, ReportSummary, Finding, Evidence, RequestResponse, Reference, ReportFormat, ReportManager, Severity};
use crate::core::target::{TargetManager, Target, TargetSpecifier, target_specifier_to_string};
use crate::core::parallel::TaskResult;
use crate::core::task_generator::{TaskGenerator, TaskGeneratorConfig, TaskType};

#[derive(Parser)]
#[command(name = "bbhunt")]
#[command(about = "A modular bug bounty hunting framework")]
pub struct BBHuntCli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new target for reconnaissance
    Target {
        #[command(subcommand)]
        subcommand: TargetSubcommand,
    },

    Parallel {
        #[arg(short, long, help = "Path to task definition file")]
        tasks: Option<PathBuf>,
        
        #[arg(short, long, help = "Path to output results")]
        output: Option<PathBuf>,
        
        #[arg(short, long, default_value = "4", help = "Maximum concurrent tasks")]
        concurrent: usize,
    },
    
    /// Generate reports
    Report {
        #[arg(short, long, help = "Target name")]
        target: String,
        
        #[arg(short, long, help = "Report format (json, md, html)")]
        format: Vec<String>,
        
        #[arg(short, long, help = "Output directory")]
        output: Option<PathBuf>,
        
        #[arg(short, long, help = "Report title")]
        title: Option<String>,
    },

    /// Run a specific plugin
    Run {
        #[arg(help = "Plugin name to run")]
        plugin: String,

        #[arg(help = "Target domain")]
        target: String,

        #[arg(long, help = "JSON-formatted options")]
        options: Option<String>,
    },

    /// List available plugins
    Plugins {
        #[arg(long, help = "Filter by category")]
        category: Option<String>,
    },

    GenerateTasks {
        #[arg(short, long, help = "Input results file")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output tasks file")]
        output: PathBuf,
        
        #[arg(short, long, help = "Task type (recon, scan, exploit)")]
        r#type: String,
        
        #[arg(long, help = "Plugins to use (comma-separated)")]
        plugins: Option<String>,
        
        #[arg(long, default_value = "10", help = "Maximum targets per task")]
        max_targets: usize,
        
        #[arg(long, help = "JSON-formatted options")]
        options: Option<String>,
    },

    /// Show system resource usage
    Resources,

    /// Start an interactive session
    Interactive,
}

#[derive(Subcommand)]
enum TargetSubcommand {
    /// Add a new target
    Add {
        #[arg(help = "Target name")]
        name: String,
        
        #[arg(long, help = "Domain to include")]
        domain: Option<Vec<String>>,
        
        #[arg(long, help = "IP address to include")]
        ip: Option<Vec<String>>,
        
        #[arg(long, help = "CIDR range to include")]
        cidr: Option<Vec<String>>,
    },
    
    /// Add includes to target scope
    Include {
        #[arg(help = "Target name")]
        name: String,
        
        #[arg(long, help = "Domain to include")]
        domain: Option<String>,
        
        #[arg(long, help = "IP address to include")]
        ip: Option<String>,
        
        #[arg(long, help = "CIDR range to include")]
        cidr: Option<String>,
    },
    
    /// Add excludes to target scope
    Exclude {
        #[arg(help = "Target name")]
        name: String,
        
        #[arg(long, help = "Domain to exclude")]
        domain: Option<String>,
        
        #[arg(long, help = "IP address to exclude")]
        ip: Option<String>,
        
        #[arg(long, help = "CIDR range to exclude")]
        cidr: Option<String>,
    },
    
    /// List targets
    List,
    
    /// Show target details
    Show {
        #[arg(help = "Target name")]
        name: String,
    },
    
    /// Export targets to file
    Export {
        #[arg(help = "Output file path")]
        path: PathBuf,
    },
    
    /// Import targets from file
    Import {
        #[arg(help = "Input file path")]
        path: PathBuf,
    },
}

impl BBHuntCli {
    pub fn new() -> Self {
        Self::parse()
    }

    pub async fn run(&self) -> Result<()> {
        // Initialize core components
        let mut config = BBHuntConfig::load(None)?;
        let resource_manager = ResourceManager::new();
        let mut plugin_manager = PluginManager::new();

        // Load plugins
        plugin_manager.load_plugins(&config.global.config_dir.join("plugins")).await?;

        match &self.command {
            Some(Commands::Target { subcommand }) => {
                let mut target_manager = TargetManager::new();
                
                // Load existing targets if available
                let targets_file = config.global.config_dir.join("targets.json");
                if targets_file.exists() {
                    target_manager.import_targets(&targets_file)?;
                }
                
                match subcommand {
                    TargetSubcommand::Add { name, domain, ip, cidr } => {
                        let mut includes = Vec::new();
                        
                        if let Some(domains) = domain {
                            for d in domains {
                                includes.push(TargetSpecifier::Domain(d));
                            }
                        }
                        
                        if let Some(ips) = ip {
                            for i in ips {
                                let ip_addr = i.parse::<std::net::IpAddr>()
                                    .context(format!("Invalid IP address: {}", i))?;
                                includes.push(TargetSpecifier::Ip(ip_addr));
                            }
                        }
                        
                        if let Some(cidrs) = cidr {
                            for c in cidrs {
                                let network = c.parse::<ipnetwork::IpNetwork>()
                                    .context(format!("Invalid CIDR notation: {}", c))?;
                                includes.push(TargetSpecifier::CidrRange(network));
                            }
                        }
                        
                        let target = Target {
                            name: name.clone(),
                            includes,
                            excludes: Vec::new(),
                            tags: HashMap::new(),
                            notes: None,
                            added_at: chrono::Utc::now(),
                        };
                        
                        target_manager.add_target(target)?;
                        println!("Added target: {}", name);
                    },
                    
                    TargetSubcommand::Include { name, domain, ip, cidr } => {
                        if let Some(domain_str) = domain {
                            target_manager.add_include(&name, TargetSpecifier::Domain(domain_str))?;
                            println!("Added domain {} to target {}", domain_str, name);
                        }
                        
                        if let Some(ip_str) = ip {
                            let ip_addr = ip_str.parse::<std::net::IpAddr>()
                                .context(format!("Invalid IP address: {}", ip_str))?;
                            target_manager.add_include(&name, TargetSpecifier::Ip(ip_addr))?;
                            println!("Added IP {} to target {}", ip_str, name);
                        }
                        
                        if let Some(cidr_str) = cidr {
                            let network = cidr_str.parse::<ipnetwork::IpNetwork>()
                                .context(format!("Invalid CIDR notation: {}", cidr_str))?;
                            target_manager.add_include(&name, TargetSpecifier::CidrRange(network))?;
                            println!("Added CIDR {} to target {}", cidr_str, name);
                        }
                    },
                    
                    TargetSubcommand::Exclude { name, domain, ip, cidr } => {
                        if let Some(domain_str) = domain {
                            target_manager.add_exclude(&name, TargetSpecifier::Domain(domain_str))?;
                            println!("Added domain exclusion {} to target {}", domain_str, name);
                        }
                        
                        if let Some(ip_str) = ip {
                            let ip_addr = ip_str.parse::<std::net::IpAddr>()
                                .context(format!("Invalid IP address: {}", ip_str))?;
                            target_manager.add_exclude(&name, TargetSpecifier::Ip(ip_addr))?;
                            println!("Added IP exclusion {} to target {}", ip_str, name);
                        }
                        
                        if let Some(cidr_str) = cidr {
                            let network = cidr_str.parse::<ipnetwork::IpNetwork>()
                                .context(format!("Invalid CIDR notation: {}", cidr_str))?;
                            target_manager.add_exclude(&name, TargetSpecifier::CidrRange(network))?;
                            println!("Added CIDR exclusion {} to target {}", cidr_str, name);
                        }
                    },
                    
                    TargetSubcommand::List => {
                        println!("Available targets:");
                        for (name, target) in target_manager.get_all_targets() {
                            println!("- {} (added: {})", name, target.added_at.format("%Y-%m-%d"));
                        }
                    },
                    
                    TargetSubcommand::Show { name } => {
                        let target = target_manager.get_target(&name)?;
                        println!("Target: {}", target.name);
                        println!("Added: {}", target.added_at.format("%Y-%m-%d %H:%M:%S"));
                        
                        println!("\nIncludes:");
                        for include in &target.includes {
                            println!("- {}", target_specifier_to_string(include));
                        }
                        
                        println!("\nExcludes:");
                        for exclude in &target.excludes {
                            println!("- {}", target_specifier_to_string(exclude));
                        }
                        
                        if let Some(notes) = &target.notes {
                            println!("\nNotes: {}", notes);
                        }
                        
                        println!("\nTags:");
                        for (key, value) in &target.tags {
                            println!("- {}: {}", key, value);
                        }
                    },
                    
                    TargetSubcommand::Export { path } => {
                        target_manager.export_targets(&path)?;
                        println!("Exported targets to {}", path.display());
                    },
                    
                    TargetSubcommand::Import { path } => {
                        target_manager.import_targets(&path)?;
                        println!("Imported targets from {}", path.display());
                    },
                }
                
                // Save updated targets
                target_manager.export_targets(&targets_file)?;
            }
            Some(Commands::Run { plugin, target, options }) => {
                // Parse options from JSON if provided
                let parsed_options = options
                    .as_ref()
                    .map(|opts| serde_json::from_str(opts).context("Invalid JSON options"))
                    .transpose()?;

                let result = plugin_manager.run_plugin(plugin, target, parsed_options).await?;
                self.display_plugin_result(&result);
            }
            Some(Commands::Plugins { category }) => {
                // Implement plugin listing logic
                println!("Available plugins...");
            }
            Some(Commands::Report { target, format, output, title }) => {
                let output_dir = output.unwrap_or_else(|| PathBuf::from("./reports"));
                
                // Ensure output directory exists
                if !output_dir.exists() {
                    std::fs::create_dir_all(&output_dir)?;
                }
                
                let report_title = title.unwrap_or_else(|| format!("Security Report for {}", target));
                
                // Create report manager
                let report_manager = ReportManager::new(output_dir.clone());
                
                // Load target information
                let mut target_manager = TargetManager::new();
                let targets_file = config.global.config_dir.join("targets.json");
                if targets_file.exists() {
                    target_manager.import_targets(&targets_file)?;
                }
                
                // Load scan results (simplified - you'd need to implement result storage)
                let scan_results = load_scan_results_for_target(&target)?;
                
                // Build report based on scan results
                let mut report = Report {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: report_title,
                    created_at: chrono::Utc::now(),
                    target: target.clone(),
                    summary: ReportSummary {
                        total_hosts_scanned: 0,
                        total_findings: 0,
                        severity_counts: HashMap::new(),
                        start_time: chrono::Utc::now(), // You'd use actual scan start time
                        end_time: chrono::Utc::now(),   // You'd use actual scan end time
                        duration_seconds: 0,            // Calculate from start/end time
                    },
                    findings: Vec::new(),
                    metadata: HashMap::new(),
                };
                
                // Process scan results into findings
                for result in scan_results {
                    if let Some(plugin_result) = result.result {
                        // Process vulnerability data from web_scan plugin
                        if let Some(Value::Array(vulnerabilities)) = plugin_result.data.get("vulnerabilities") {
                            for vuln_value in vulnerabilities {
                                if let Ok(vuln) = serde_json::from_value::<VulnerabilityData>(vuln_value.clone()) {
                                    let finding = convert_vulnerability_to_finding(vuln, &result.task_id);
                                    report.findings.push(finding);
                                }
                            }
                        }
                    }
                }
                
                // Update summary
                report.summary.total_findings = report.findings.len();
                report.summary.total_hosts_scanned = target_manager.resolve_target(&target)?.len();
                
                // Count severity levels
                let mut severity_counts = HashMap::new();
                for finding in &report.findings {
                    *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
                }
                report.summary.severity_counts = severity_counts;
                
                // Generate reports in requested formats
                let format_types: Vec<ReportFormat> = format
                    .iter()
                    .map(|f| match f.as_str() {
                        "json" => ReportFormat::JSON,
                        "md" | "markdown" => ReportFormat::Markdown,
                        "html" => ReportFormat::HTML,
                        "pdf" => ReportFormat::PDF,
                        "csv" => ReportFormat::CSV,
                        "xml" => ReportFormat::XML,
                        _ => ReportFormat::JSON, // Default to JSON for unknown formats
                    })
                    .collect();
                
                let report_paths = report_manager.generate_multi_format(&report, &format_types).await?;
                
                println!("Generated {} report(s):", report_paths.len());
                for path in report_paths {
                    println!("- {}", path.display());
                }
            }
            Some(Commands::Resources) => {
                let usage = resource_manager.get_resource_usage().await?;
                println!("{:#?}", usage);
            }
            Some(Commands::GenerateTasks { input, output, r#type, plugins, max_targets, options }) => {
                let task_type = match r#type.as_str() {
                    "recon" => TaskType::Recon,
                    "scan" => TaskType::Scan,
                    "exploit" => TaskType::Exploit,
                    _ => return Err(anyhow::anyhow!("Invalid task type: {}", r#type)),
                };
                
                let plugins_list = plugins
                    .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_else(|| {
                        // Default plugins based on task type
                        match task_type {
                            TaskType::Recon => vec!["subdomain_enum".to_string()],
                            TaskType::Scan => vec!["web_scan".to_string()],
                            TaskType::Exploit => vec![],
                        }
                    });
                
                let parsed_options = options
                    .as_ref()
                    .map(|opts| serde_json::from_str(opts).context("Invalid JSON options"))
                    .transpose()?
                    .unwrap_or_else(|| HashMap::new());
                
                let generator_config = TaskGeneratorConfig {
                    task_type,
                    plugins: plugins_list,
                    max_targets_per_task: max_targets,
                    options: parsed_options,
                };
                
                let generator = TaskGenerator::new(generator_config);
                let tasks = generator.generate_from_results(&input)?;
                generator.save_tasks(&tasks, &output)?;
                
                println!("Generated {} tasks and saved to {}", tasks.len(), output.display());
            }
            Some(Commands::Interactive) => {
                self.start_interactive_session(&mut config, &mut plugin_manager).await?;
            }
            None => {
                self.show_help();
            }
        }

        Ok(())
    }

    fn display_plugin_result(&self, result: &PluginResult) {
        match result.status {
            PluginResult::Success => {
                println!("Plugin executed successfully!");
                println!("Message: {}", result.message);
                // Pretty print result data
                println!("Data: {:#?}", result.data);
            }
            PluginResult::Error => {
                eprintln!("Plugin execution failed!");
                eprintln!("Error: {}", result.message);
            }
            PluginResult::Partial => {
                println!("Plugin partially completed.");
                println!("Message: {}", result.message);
            }
        }
    }

    async fn start_interactive_session(
        &self, 
        config: &mut BBHuntConfig, 
        plugin_manager: &mut PluginManager
    ) -> Result<()> {
        loop {
            let action: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("bbhunt")
                .interact_text()?;

            match action.as_str() {
                "exit" | "quit" => break,
                "help" => self.show_help(),
                _ => {
                    println!("Unknown command. Type 'help' for assistance.");
                }
            }
        }
        Ok(())
    }

    fn show_help(&self) {
        println!("BBHunt - Bug Bounty Hunting Framework");
        println!("Available commands:");
        println!("  target <domain>     Add a new target");
        println!("  run <plugin> <target>  Run a specific plugin");
        println!("  plugins             List available plugins");
        println!("  resources           Show system resource usage");
        println!("  interactive         Start interactive session");
        println!("  help                Show this help message");
    }

    fn convert_vulnerability_to_finding(vuln: VulnerabilityData, plugin_name: &str) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            title: vuln.name,
            description: vuln.description,
            severity: vuln.severity,
            cvss_score: vuln.cvss_score,
            cve_ids: vuln.cve_ids.unwrap_or_default(),
            affected_targets: vec![vuln.url],
            evidence: Evidence {
                description: vuln.evidence_description.unwrap_or_else(|| "No evidence description provided".to_string()),
                data: vuln.details.unwrap_or_default().into(),
                screenshots: Vec::new(),
                request_response: vuln.request_response.map(|rr| RequestResponse {
                    request: rr.request,
                    response: rr.response,
                    status_code: rr.status_code,
                    headers: rr.headers,
                }),
            },
            remediation: vuln.remediation,
            references: vuln.references.unwrap_or_default().into_iter()
                .map(|r| Reference {
                    title: r.title,
                    url: r.url,
                    source_type: r.source_type,
                })
                .collect(),
            tags: vuln.tags.unwrap_or_default(),
            discovered_by: plugin_name.to_string(),
            discovered_at: chrono::Utc::now(),
        }
    }
    
    // Helper struct for parsing vulnerability data from plugin results
    #[derive(Debug, Deserialize)]
    struct VulnerabilityData {
        name: String,
        description: String,
        severity: Severity,
        url: String,
        cvss_score: Option<f32>,
        cve_ids: Option<Vec<String>>,
        evidence_description: Option<String>,
        details: Option<HashMap<String, Value>>,
        remediation: Option<String>,
        references: Option<Vec<ReferenceData>>,
        tags: Option<Vec<String>>,
        request_response: Option<RequestResponseData>,
    }
    
    #[derive(Debug, Deserialize)]
    struct ReferenceData {
        title: String,
        url: String,
        source_type: ReferenceType,
    }
    
    #[derive(Debug, Deserialize)]
    struct RequestResponseData {
        request: String,
        response: String,
        status_code: u16,
        headers: HashMap<String, String>,
    }
    
    // Helper function to load scan results for a target
    fn load_scan_results_for_target(target: &str) -> Result<Vec<crate::core::parallel::TaskResult>> {
        // In a real implementation, you would load results from a database or file
        // This is a simplified placeholder
        let results_dir = std::path::PathBuf::from("./results");
        if !results_dir.exists() { return Err(anyhow::anyhow!("Results directory not found")); }
        let files = std::fs::read_dir(results_dir).context("Failed to read results directory")?;
        let mut all_results = Vec::new();
        
        for file in files {
            let file = file?;
            let path = file.path();
            
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                let content = std::fs::read_to_string(&path)?;
                let results: Vec<crate::core::parallel::TaskResult> = serde_json::from_str(&content)?;
                
                // Filter results for this target
                for result in results {
                    if result.task_id.contains(target) {
                        all_results.push(result);
                    }
                }
            }
        }
        
        Ok(all_results)
    }
}
