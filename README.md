# BBHunt - Bug Bounty Hunting Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.75+-orange.svg)

## Overview

BBHunt is a comprehensive, modular bug bounty hunting framework designed to streamline and automate reconnaissance, scanning, and vulnerability detection across various targets.

## Features

- 🚀 **Modular Plugin Architecture**: Easily extend with new tools and capabilities
- 🔒 **Cross-Platform Support**: Works on Linux, macOS, and Windows
- 📊 **Comprehensive Scanning**: Integrated vulnerability scanning and reporting
- 🛡️ **Resource-Aware Execution**: Efficient resource allocation and monitoring
- 🔍 **Advanced Reconnaissance**: Subdomain discovery, service enumeration, and more
- 📑 **Flexible Reporting**: Multiple output formats (JSON, Markdown, HTML)
- 🔄 **Parallel Processing**: Run tasks concurrently for faster results
- 🌐 **CIDR & Scope Management**: Precise target definition with inclusions/exclusions
- 🐳 **Docker Integration**: Containerized execution for isolation and reproducibility
- 🔌 **CI/CD Integration**: Automate security scanning with GitHub Actions and more

## Installation

### Prerequisites

- Rust 1.75 or later
- Optional external tools:
 - Subfinder
 - Amass
 - Nuclei
 - Nikto

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/bbhunt.git
cd bbhunt

# Build the project
cargo build --release

# Install the binary
cargo install --path .