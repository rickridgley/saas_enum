# SaaS Enum

SaaS Enum is a command line tool for discovering the SaaS platforms a company may be using. The tool looks for DNS entries that match known provider patterns and optionally performs lightweight web checks for confirmation.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
### Basic check
Provide the company short name (subdomain) to test against all providers:
```bash
python saas_enum.py -i example
```

### Batch mode
Process multiple companies from a file and save the results as CSV:
```bash
python saas_enum.py -b companies.txt -o results.csv -f csv
```

### List providers
Display all provider templates defined in `dns_integrations.yaml`:
```bash
python saas_enum.py --list-providers
```

## Command line options
- `-i`, `--input` SHORT_NAME  
  Short name of the company to check.
- `-b`, `--batch` FILE  
  File containing multiple short names to check (one per line).
- `-p`, `--providers` NAMES  
  Comma separated list of specific providers to check.
- `-j`, `--json`  
  Output results in JSON format when used with a single check.
- `-o`, `--output` FILE  
  Save output to the specified file.
- `-f`, `--format` {text,json,csv}  
  Output format for saved results. Defaults to `text`.
- `-w`, `--workers` NUM  
  Maximum number of concurrent worker threads (default: 10).
- `-l`, `--list-providers`  
  List all available providers and exit.
- `-c`, `--check-providers`  
  Validate provider patterns for wildcard DNS.
- `-y`, `--yaml` PATH  
  Path to the provider definition YAML file (default: `dns_integrations.yaml`).
- `-t`, `--timeout` SECONDS  
  Timeout in seconds for each provider check (default: 20).
- `-v`, `--verbose`  
  Show detailed output for all checks.

The supporting modules are located in the `modules` directory.

## Features
- DNS-based SaaS provider enumeration
- Optional HTTP verification of provider pages
- Batch processing with CSV or JSON reporting

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
