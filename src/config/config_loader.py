#!/usr/bin/env python3
"""
DAY 9: Configuration File Support
"""

import os
import json
import yaml
from pathlib import Path

class ConfigLoader:
    """Loads and manages configuration for the security scanner"""
    
    DEFAULT_CONFIG = {
        'general': {
            'project_name': 'Database Security Static Analyzer',
            'version': '1.0',
            'author': 'User'
        },
        'analysis': {
            'default_analyzers': ['sql', 'secrets', 'db', 'input'],
            'scan_hidden_files': False,
            'max_file_size_mb': 10,
            'follow_symlinks': False
        },
        'severity': {
            'high_threshold': 3,
            'medium_threshold': 5,
            'fail_on_high': True,
            'warn_on_medium': True
        },
        'reports': {
            'default_format': 'html',
            'output_directory': './reports',
            'timestamp_format': '%Y%m%d_%H%M%S',
            'auto_open_html': True
        },
        'analyzers': {
            'sql_injection': {
                'enabled': True,
                'severity': 'HIGH',
                'check_f_strings': True,
                'check_string_concat': True
            },
            'hardcoded_secrets': {
                'enabled': True,
                'severity': 'HIGH',
                'min_secret_length': 8,
                'check_variable_names': True
            },
            'database_connection': {
                'enabled': True,
                'severity': 'MEDIUM',
                'check_credentials': True,
                'check_ssl': True
            },
            'input_validation': {
                'enabled': True,
                'severity': 'MEDIUM',
                'check_eval': True,
                'check_exec': True
            }
        },
        'ignore': {
            'patterns': [
                '**/__pycache__/**',
                '**/.git/**',
                '**/venv/**',
                '**/node_modules/**'
            ]
        }
    }
    
    def __init__(self, config_path=None):
        """Initialize config loader with optional config file"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_path = config_path
        
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
        elif config_path:
            print(f"⚠️  Config file not found: {config_path}")
            print("📋 Using default configuration")
        else:
            # Don't print anything if no config path provided
            pass
    
    def load_config(self, config_path):
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.json'):
                    user_config = json.load(f)
                else:
                    # Try YAML for all other extensions
                    user_config = yaml.safe_load(f)
            
            if user_config:
                # Merge user config with default config
                self._merge_configs(self.config, user_config)
                self.config_path = config_path
                return True
            else:
                print(f"⚠️  Config file is empty: {config_path}")
                return False
                
        except yaml.YAMLError as e:
            print(f"❌ YAML parsing error in {config_path}: {e}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing error in {config_path}: {e}")
            return False
        except Exception as e:
            print(f"❌ Error loading config {config_path}: {e}")
            return False
    
    def _merge_configs(self, default, user):
        """Recursively merge user config into default config"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_configs(default[key], value)
            else:
                default[key] = value
    
    def save_config(self, config_path='security_config.yaml'):
        """Save current configuration to file"""
        try:
            # Convert to absolute path
            config_path = os.path.abspath(config_path)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                if config_path.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                else:
                    yaml.dump(self.config, f, default_flow_style=False)
            
            self.config_path = config_path
            return True
            
        except Exception as e:
            print(f"❌ Error saving config to {config_path}: {e}")
            return False
    
    def get(self, key, default=None):
        """Get configuration value by dot notation key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key, value):
        """Set configuration value by dot notation key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_enabled_analyzers(self):
        """Get list of enabled analyzers from config"""
        enabled = []
        analyzers_config = self.get('analyzers', {})
        
        analyzer_map = {
            'sql_injection': 'sql',
            'hardcoded_secrets': 'secrets',
            'database_connection': 'db',
            'input_validation': 'input'
        }
        
        for analyzer_name, config in analyzers_config.items():
            if config.get('enabled', True):
                short_name = analyzer_map.get(analyzer_name, analyzer_name)
                enabled.append(short_name)
        
        return enabled or ['sql', 'secrets', 'db', 'input']
    
    def should_ignore_file(self, file_path):
        """Check if a file should be ignored based on patterns"""
        ignore_patterns = self.get('ignore.patterns', [])
        
        for pattern in ignore_patterns:
            # Simple pattern matching
            if pattern.replace('**/', '').replace('/**', '') in file_path:
                return True
        
        return False
    
    def print_summary(self):
        """Print configuration summary"""
        enabled_analyzers = self.get_enabled_analyzers()
        print(f"✓ Enabled Analyzers: {', '.join(enabled_analyzers)}")
        
        report_format = self.get('reports.default_format', 'html')
        print(f"✓ Default Report Format: {report_format}")
        
        high_threshold = self.get('severity.high_threshold', 3)
        print(f"✓ High Severity Threshold: {high_threshold} issues")
        
        output_dir = self.get('reports.output_directory', './reports')
        print(f"✓ Output Directory: {output_dir}")
        
        ignore_patterns = len(self.get('ignore.patterns', []))
        print(f"✓ Ignore Patterns: {ignore_patterns} patterns")
