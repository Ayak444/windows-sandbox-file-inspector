"""Keep Chinese PowerShell source compatible with Windows PowerShell 5.1."""
from pathlib import Path

root = Path(__file__).resolve().parent
for relative in (
    'guest-tools/File-Inspector.Core.ps1',
    'Test-File-Inspector.ps1',
    'guest-tools/Test-Guest-Inspector.ps1',
):
    path = root / relative
    source = path.read_text(encoding='utf-8-sig')
    path.write_text(source, encoding='utf-8-sig')
