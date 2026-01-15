"""Tests for configuration management"""

from securevibes.config import LanguageConfig, ScanConfig


class TestLanguageConfig:
    """Test LanguageConfig class"""

    def test_supported_languages(self):
        """Test that all expected languages are supported"""
        expected_languages = {
            "python",
            "javascript",
            "typescript",
            "go",
            "ruby",
            "java",
            "php",
            "csharp",
            "rust",
            "kotlin",
            "swift",
        }
        assert set(LanguageConfig.SUPPORTED_LANGUAGES.keys()) == expected_languages

    def test_python_extensions(self):
        """Test Python file extensions"""
        assert ".py" in LanguageConfig.SUPPORTED_LANGUAGES["python"]

    def test_javascript_extensions(self):
        """Test JavaScript file extensions"""
        js_exts = LanguageConfig.SUPPORTED_LANGUAGES["javascript"]
        assert ".js" in js_exts
        assert ".jsx" in js_exts

    def test_typescript_extensions(self):
        """Test TypeScript file extensions"""
        ts_exts = LanguageConfig.SUPPORTED_LANGUAGES["typescript"]
        assert ".ts" in ts_exts
        assert ".tsx" in ts_exts

    def test_go_extensions(self):
        """Test Go file extensions"""
        assert ".go" in LanguageConfig.SUPPORTED_LANGUAGES["go"]

    def test_ruby_extensions(self):
        """Test Ruby file extensions"""
        assert ".rb" in LanguageConfig.SUPPORTED_LANGUAGES["ruby"]

    def test_java_extensions(self):
        """Test Java file extensions"""
        assert ".java" in LanguageConfig.SUPPORTED_LANGUAGES["java"]

    def test_get_all_extensions(self):
        """Test getting all extensions"""
        all_exts = LanguageConfig.get_all_extensions()

        # Check some expected extensions
        assert ".py" in all_exts
        assert ".js" in all_exts
        assert ".go" in all_exts
        assert ".rb" in all_exts

        # Should be a set
        assert isinstance(all_exts, set)

    def test_detect_languages_with_python(self, tmp_path):
        """Test language detection with Python files"""
        # Create Python files
        (tmp_path / "main.py").touch()
        (tmp_path / "test.py").touch()

        languages = LanguageConfig.detect_languages(tmp_path)
        assert "python" in languages

    def test_detect_languages_with_multiple_languages(self, tmp_path):
        """Test language detection with multiple languages"""
        # Create files in different languages
        (tmp_path / "main.py").touch()
        (tmp_path / "app.js").touch()
        (tmp_path / "server.go").touch()

        languages = LanguageConfig.detect_languages(tmp_path)
        assert "python" in languages
        assert "javascript" in languages
        assert "go" in languages

    def test_detect_languages_empty_repo(self, tmp_path):
        """Test language detection with empty repository"""
        languages = LanguageConfig.detect_languages(tmp_path)
        assert len(languages) == 0

    def test_detect_languages_with_subdirectories(self, tmp_path):
        """Test language detection with files in subdirectories"""
        # Create nested structure
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "main.py").touch()

        languages = LanguageConfig.detect_languages(tmp_path)
        assert "python" in languages


class TestScanConfig:
    """Test ScanConfig class"""

    def test_common_excluded_dirs(self):
        """Test common infrastructure directories"""
        common = ScanConfig.EXCLUDED_DIRS_COMMON

        assert ".claude" in common
        assert ".git" in common
        assert "dist" in common
        assert "build" in common

    def test_python_excluded_dirs(self):
        """Test Python-specific exclusions"""
        python_dirs = ScanConfig.EXCLUDED_DIRS_PYTHON

        assert "venv" in python_dirs
        assert ".venv" in python_dirs
        assert "__pycache__" in python_dirs
        assert ".pytest_cache" in python_dirs

    def test_javascript_excluded_dirs(self):
        """Test JavaScript-specific exclusions"""
        js_dirs = ScanConfig.EXCLUDED_DIRS_JS

        assert "node_modules" in js_dirs
        assert ".next" in js_dirs
        assert ".nuxt" in js_dirs

    def test_go_excluded_dirs(self):
        """Test Go-specific exclusions"""
        go_dirs = ScanConfig.EXCLUDED_DIRS_GO

        assert "vendor" in go_dirs
        assert "bin" in go_dirs

    def test_get_excluded_dirs_no_languages(self):
        """Test exclusions with no languages specified"""
        dirs = ScanConfig.get_excluded_dirs(None)

        # Should include common dirs
        assert ".git" in dirs
        assert "dist" in dirs

        # Should include all language-specific dirs
        assert "node_modules" in dirs  # JS
        assert "__pycache__" in dirs  # Python
        assert "vendor" in dirs  # Go/Ruby

    def test_get_excluded_dirs_python_only(self):
        """Test exclusions for Python-only project"""
        dirs = ScanConfig.get_excluded_dirs({"python"})

        # Should include common and Python dirs
        assert ".git" in dirs
        assert "__pycache__" in dirs
        assert "venv" in dirs

        # Should NOT include JS-specific dirs
        assert "node_modules" not in dirs

    def test_get_excluded_dirs_javascript_only(self):
        """Test exclusions for JavaScript-only project"""
        dirs = ScanConfig.get_excluded_dirs({"javascript"})

        # Should include common and JS dirs
        assert ".git" in dirs
        assert "node_modules" in dirs

        # Should NOT include Python-specific dirs
        assert "__pycache__" not in dirs
        assert "venv" not in dirs

    def test_get_excluded_dirs_multi_language(self):
        """Test exclusions for multi-language project"""
        dirs = ScanConfig.get_excluded_dirs({"python", "javascript", "go"})

        # Should include all relevant dirs
        assert "__pycache__" in dirs  # Python
        assert "node_modules" in dirs  # JS
        assert "vendor" in dirs  # Go

    def test_get_excluded_dirs_for_phase_assessment(self):
        """Test phase-specific exclusions for assessment phase"""
        dirs = ScanConfig.get_excluded_dirs_for_phase("assessment", {"python"})

        # Should include .claude during assessment
        assert ".claude" in dirs

    def test_get_excluded_dirs_for_phase_dast(self):
        """Test phase-specific exclusions for DAST phase"""
        dirs = ScanConfig.get_excluded_dirs_for_phase("dast", {"python"})

        # Should NOT include .claude during DAST (needs skills access)
        assert ".claude" not in dirs

        # But should still include other exclusions
        assert ".git" in dirs
        assert "__pycache__" in dirs

    def test_blocked_db_tools(self):
        """Test database tools blocking list"""
        blocked = ScanConfig.BLOCKED_DB_TOOLS

        # Check common database CLIs
        assert "sqlite3" in blocked
        assert "psql" in blocked
        assert "mysql" in blocked
        assert "mongosh" in blocked
        assert "redis-cli" in blocked

    def test_blocked_db_tools_is_list(self):
        """Test that blocked tools is a list (not set)"""
        # Should be a list for consistent ordering in error messages
        assert isinstance(ScanConfig.BLOCKED_DB_TOOLS, list)


class TestLanguageDetectionIntegration:
    """Integration tests for language detection and exclusions"""

    def test_python_project_excludes_python_dirs(self, tmp_path):
        """Test that Python project gets Python-specific exclusions"""
        # Create Python project structure
        (tmp_path / "main.py").touch()
        (tmp_path / "venv").mkdir()

        # Detect languages
        languages = LanguageConfig.detect_languages(tmp_path)

        # Get exclusions
        dirs = ScanConfig.get_excluded_dirs(languages)

        # Should exclude Python-specific directories
        assert "venv" in dirs
        assert "__pycache__" in dirs

    def test_js_project_excludes_js_dirs(self, tmp_path):
        """Test that JS project gets JS-specific exclusions"""
        # Create JS project structure
        (tmp_path / "index.js").touch()
        (tmp_path / "node_modules").mkdir()

        # Detect languages
        languages = LanguageConfig.detect_languages(tmp_path)

        # Get exclusions
        dirs = ScanConfig.get_excluded_dirs(languages)

        # Should exclude JS-specific directories
        assert "node_modules" in dirs

    def test_mixed_project_excludes_both(self, tmp_path):
        """Test that mixed project gets exclusions for all languages"""
        # Create mixed project
        (tmp_path / "backend.py").touch()
        (tmp_path / "frontend.js").touch()

        # Detect languages
        languages = LanguageConfig.detect_languages(tmp_path)

        # Get exclusions
        dirs = ScanConfig.get_excluded_dirs(languages)

        # Should exclude both Python and JS directories
        assert "venv" in dirs
        assert "node_modules" in dirs
