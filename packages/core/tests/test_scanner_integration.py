"""
Integration tests for Scanner file scanning and language detection logic.

These tests validate the scanner's file counting and language detection WITHOUT
running full Claude scans. They test the core logic that was added in the
multi-language support feature.

For true end-to-end tests with real Claude execution, see test_scanner.py which
mocks ClaudeSDKClient.
"""

import pytest
from pathlib import Path
from securevibes.config import LanguageConfig, ScanConfig


class TestLanguageDetectionIntegration:
    """Integration tests for language detection on real file structures"""
    
    @pytest.mark.integration
    def test_detects_python_files(self, tmp_path):
        """Test language detection finds Python files"""
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'python' in detected
    
    @pytest.mark.integration
    def test_detects_multiple_languages(self, tmp_path):
        """Test detection of multiple languages in one project"""
        (tmp_path / "backend.py").write_text("def api(): pass")
        (tmp_path / "server.go").write_text("package main")
        (tmp_path / "app.js").write_text("console.log('hello')")
        (tmp_path / "component.tsx").write_text("export const App = () => null")
        (tmp_path / "main.rb").write_text("puts 'hello'")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'python' in detected
        assert 'go' in detected
        assert 'javascript' in detected or 'typescript' in detected
        assert 'ruby' in detected
    
    @pytest.mark.integration
    def test_handles_nested_directories(self, tmp_path):
        """Test detection works with nested directory structures"""
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("print('hello')")
        
        api = src / "api"
        api.mkdir()
        (api / "routes.go").write_text("package api")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'python' in detected
        assert 'go' in detected
    
    @pytest.mark.integration
    def test_empty_repository(self, tmp_path):
        """Test handles repository with no code files"""
        (tmp_path / "README.md").write_text("# Empty project")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert len(detected) == 0


class TestFileCountingLogic:
    """Integration tests for file counting with language-aware exclusions"""
    
    @pytest.mark.integration
    def test_counts_python_files_excludes_venv(self, tmp_path):
        """Test counts Python files but excludes venv"""
        # Create Python files
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")
        
        # Create venv (should be excluded)
        venv = tmp_path / "venv"
        venv.mkdir()
        (venv / "lib.py").write_text("# Should not count")
        
        # Detect language and get exclusions
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'python' in detected
        
        exclusions = ScanConfig.get_excluded_dirs(detected)
        assert 'venv' in exclusions
        assert '__pycache__' in exclusions
        
        # Count files manually (simulating scanner logic)
        code_files = []
        for ext in LanguageConfig.SUPPORTED_LANGUAGES['python']:
            for file in tmp_path.rglob(f"*{ext}"):
                # Check if file is in excluded dir
                is_excluded = any(part in exclusions for part in file.relative_to(tmp_path).parts)
                if not is_excluded:
                    code_files.append(file)
        
        assert len(code_files) == 2  # Only app.py and utils.py
    
    @pytest.mark.integration
    def test_counts_js_files_excludes_node_modules(self, tmp_path):
        """Test counts JS files but excludes node_modules"""
        # Create JS files
        (tmp_path / "index.js").write_text("const x = 1")
        (tmp_path / "app.js").write_text("const y = 2")
        
        # Create node_modules (should be excluded)
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "lodash.js").write_text("// Should not count")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'javascript' in detected
        
        exclusions = ScanConfig.get_excluded_dirs(detected)
        assert 'node_modules' in exclusions
        
        # Count files
        code_files = []
        for ext in LanguageConfig.SUPPORTED_LANGUAGES['javascript']:
            for file in tmp_path.rglob(f"*{ext}"):
                is_excluded = any(part in exclusions for part in file.relative_to(tmp_path).parts)
                if not is_excluded:
                    code_files.append(file)
        
        assert len(code_files) == 2  # Only index.js and app.js
    
    @pytest.mark.integration
    def test_counts_go_files_excludes_vendor(self, tmp_path):
        """Test counts Go files but excludes vendor"""
        # Create Go files
        (tmp_path / "main.go").write_text("package main")
        (tmp_path / "utils.go").write_text("package utils")
        
        # Create vendor (should be excluded)
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "lib.go").write_text("// Should not count")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'go' in detected
        
        exclusions = ScanConfig.get_excluded_dirs(detected)
        assert 'vendor' in exclusions
        
        # Count files
        code_files = []
        for ext in LanguageConfig.SUPPORTED_LANGUAGES['go']:
            for file in tmp_path.rglob(f"*{ext}"):
                is_excluded = any(part in exclusions for part in file.relative_to(tmp_path).parts)
                if not is_excluded:
                    code_files.append(file)
        
        assert len(code_files) == 2  # Only main.go and utils.go
    
    @pytest.mark.integration
    def test_mixed_language_project_file_counting(self, tmp_path):
        """Test file counting for mixed-language project"""
        # Create files in multiple languages
        (tmp_path / "backend.py").write_text("def api(): pass")
        (tmp_path / "frontend.js").write_text("console.log('hello')")
        (tmp_path / "service.go").write_text("package main")
        
        # Create excluded directories
        (tmp_path / "venv").mkdir()
        (tmp_path / "venv" / "lib.py").write_text("# excluded")
        
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text("// excluded")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        assert 'python' in detected
        assert 'javascript' in detected
        assert 'go' in detected
        
        exclusions = ScanConfig.get_excluded_dirs(detected)
        # Should have exclusions for all detected languages
        assert 'venv' in exclusions
        assert 'node_modules' in exclusions
        assert 'vendor' in exclusions


class TestExclusionLogic:
    """Integration tests for language-aware exclusion logic"""
    
    @pytest.mark.integration
    def test_python_project_excludes_python_dirs_not_js(self, tmp_path):
        """Test Python-only project doesn't unnecessarily exclude JS directories"""
        (tmp_path / "app.py").write_text("print('hello')")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        exclusions = ScanConfig.get_excluded_dirs(detected)
        
        # Should have Python exclusions
        assert 'venv' in exclusions
        assert '__pycache__' in exclusions
        
        # Should NOT have JS exclusions  
        assert 'node_modules' not in exclusions
    
    @pytest.mark.integration
    def test_js_project_excludes_js_dirs_not_python(self, tmp_path):
        """Test JS-only project doesn't unnecessarily exclude Python directories"""
        (tmp_path / "app.js").write_text("console.log('hello')")
        
        detected = LanguageConfig.detect_languages(tmp_path)
        exclusions = ScanConfig.get_excluded_dirs(detected)
        
        # Should have JS exclusions
        assert 'node_modules' in exclusions
        
        # Should NOT have Python exclusions
        assert 'venv' not in exclusions
        assert '__pycache__' not in exclusions


@pytest.mark.integration
def test_phase_aware_exclusions_for_dast():
    """Test DAST phase can access .claude/skills/ directory"""
    # Verify .claude is normally excluded
    regular_exclusions = ScanConfig.get_excluded_dirs({'python'})
    assert '.claude' in regular_exclusions
    
    # Verify .claude is NOT excluded during DAST phase
    dast_exclusions = ScanConfig.get_excluded_dirs_for_phase('dast', {'python'})
    assert '.claude' not in dast_exclusions
    
    # Both exclusion sets should still have common exclusions
    assert '.git' in regular_exclusions
    assert '.git' in dast_exclusions


@pytest.mark.integration
def test_language_aware_exclusions_logic():
    """Test that language-aware exclusions work as expected"""
    # Test 1: Python-only project
    python_exclusions = ScanConfig.get_excluded_dirs({'python'})
    assert 'venv' in python_exclusions
    assert '__pycache__' in python_exclusions
    assert 'node_modules' not in python_exclusions
    
    # Test 2: JavaScript-only project  
    js_exclusions = ScanConfig.get_excluded_dirs({'javascript'})
    assert 'node_modules' in js_exclusions
    assert 'venv' not in js_exclusions
    assert '__pycache__' not in js_exclusions
    
    # Test 3: Mixed Python + JS project
    mixed_exclusions = ScanConfig.get_excluded_dirs({'python', 'javascript'})
    assert 'venv' in mixed_exclusions
    assert 'node_modules' in mixed_exclusions
    assert '__pycache__' in mixed_exclusions
    
    # Test 4: Go project
    go_exclusions = ScanConfig.get_excluded_dirs({'go'})
    assert 'vendor' in go_exclusions
    assert 'bin' in go_exclusions
    assert 'node_modules' not in go_exclusions
    
    # Test 5: Unknown/all languages
    all_exclusions = ScanConfig.get_excluded_dirs(None)
    assert 'venv' in all_exclusions
    assert 'node_modules' in all_exclusions
    assert 'vendor' in all_exclusions


@pytest.mark.integration
def test_blocked_db_tools_accessible():
    """Test BLOCKED_DB_TOOLS is accessible and populated"""
    blocked = ScanConfig.BLOCKED_DB_TOOLS
    
    # Should be a list
    assert isinstance(blocked, list)
    assert len(blocked) > 0
    
    # Should contain common database CLIs
    assert 'sqlite3' in blocked
    assert 'psql' in blocked
    assert 'mysql' in blocked


@pytest.mark.integration
def test_language_config_has_all_declared_languages():
    """Test all declared languages have valid extensions"""
    languages = LanguageConfig.SUPPORTED_LANGUAGES
    
    # Should have expected languages
    expected = {'python', 'javascript', 'typescript', 'go', 'ruby', 
                'java', 'php', 'csharp', 'rust', 'kotlin', 'swift'}
    assert set(languages.keys()) == expected
    
    # All extensions should start with dot
    for lang, exts in languages.items():
        assert len(exts) > 0, f"{lang} has no extensions"
        for ext in exts:
            assert ext.startswith('.'), f"{lang} extension {ext} doesn't start with dot"
