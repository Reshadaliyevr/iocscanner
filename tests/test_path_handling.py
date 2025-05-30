import os
import tempfile
from pathlib import Path

def test_path_handling():
    """Debug path handling issues"""
    
    # Create a temporary file similar to your test
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        file_path = tmp_path / "eicar.com"
        file_path.write_bytes(eicar)
        
        print(f"tmp_path type: {type(tmp_path)}")
        print(f"file_path type: {type(file_path)}")
        print(f"file_path: {file_path}")
        print(f"str(file_path): {str(file_path)}")
        print(f"os.fspath(file_path): {os.fspath(file_path)}")
        print(f"os.path.abspath(str(file_path)): {os.path.abspath(str(file_path))}")
        print(f"File exists: {os.path.exists(str(file_path))}")
        print(f"File exists (fspath): {os.path.exists(os.fspath(file_path))}")
        
        # Try different approaches to open the file
        approaches = [
            str(file_path),
            os.fspath(file_path), 
            os.path.abspath(str(file_path)),
            file_path.as_posix() if hasattr(file_path, 'as_posix') else None
        ]
        
        for i, path_attempt in enumerate(approaches):
            if path_attempt is None:
                continue
            try:
                print(f"\nApproach {i+1}: {repr(path_attempt)}")
                with open(path_attempt, "rb") as f:
                    content = f.read()
                    print(f"Success! Read {len(content)} bytes")
                    break
            except Exception as e:
                print(f"Failed: {e}")

if __name__ == "__main__":
    test_path_handling()