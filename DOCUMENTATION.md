# BBHunt Profile System

BBHunt now includes a comprehensive profile system that allows you to customize scanning behavior, resource limits, and scope settings without modifying source code or configuration files.

## Profile Locations

Profiles are stored in TOML format in the following locations:

- **Default location**: `~/.bbhunt/config/profiles/` (locally)
- **Docker container**: `/config/profiles/` (when using Docker)
- **Development**: `./profiles/` (in the project directory)

## Available Profiles

BBHunt comes with several pre-configured profiles:

- **base.toml** - Default profile with standard settings
- **safe.toml** - Minimal impact profile for sensitive targets
- **audible.toml** - Profile optimized for Audible bug bounty program

## Profile Structure

Each profile consists of several sections:

```toml
[profile]
name = "base"
description = "Default base profile with standard settings"
tags = ["default", "base"]
enabled = true

[profile.resource_limits]
max_concurrent_tasks = 4
max_requests_per_second = 10
timeout_seconds = 300
# ... more resource settings

[profile.scope]
include_domains = []
exclude_domains = []
include_ips = []
exclude_ips = []
exclude_paths = []
# ... more scope settings

[profile.http]
user_agent = "bbhunt/0.1.0"
# ... more HTTP settings

[profile.tools.TOOL_NAME]
path = "tool_path"
args = ["arg1", "arg2"]
options = { option1 = "value1", option2 = "value2" }

# ... additional tool configurations