"""JSON output reporter"""

import json
from pathlib import Path
from typing import Union
from securevibes.models.result import ScanResult


class JSONReporter:
    """Saves scan results to JSON files"""
    
    @staticmethod
    def save(result: ScanResult, output_path: Union[str, Path]) -> None:
        """
        Save scan result to JSON file
        
        Args:
            result: ScanResult to save
            output_path: Path to output JSON file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    
    @staticmethod
    def load(input_path: Union[str, Path]) -> dict:
        """
        Load scan result from JSON file
        
        Args:
            input_path: Path to JSON file
            
        Returns:
            Dictionary containing scan result
        """
        with open(input_path, 'r') as f:
            return json.load(f)
