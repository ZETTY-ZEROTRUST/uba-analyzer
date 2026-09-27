"""Run from a NEW Colab checkout; reuse local arrays and avoid full Drive writes."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or not os.environ.get('COLAB_RELEASE_TAG'):
        raise SystemExit('Google-hosted Colab required; local training is disabled')
    if not (args.prepared/'dataset.json').is_file():
        raise SystemExit(f'Prepared data missing: {args.prepared}; do not delete the previous runtime')
    root = Path(__file__).resolve().parents[2]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    output = Path('/content')/f'zetty-rba-recovery-{stamp}'
    log = output.with_suffix('.log')
    command = [sys.executable, str(root/'scripts/ml/colab_rba.py'),
               '--mode', 'prepared', '--profile', 'colab-gpu-v2',
               '--prepared-local', str(args.prepared), '--output', str(output),
               '--backup-policy', 'local-only']
    print(f'OUTPUT = {str(output)!r}\nLOG = {str(log)!r}', flush=True)
    with log.open('w') as stream:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, bufsize=1)
        try:
            for line in process.stdout:
                print(line, end='', flush=True);stream.write(line);stream.flush()
            code = process.wait()
        except BaseException:
            process.terminate();process.wait()
            raise
    if code:
        raise SystemExit(f'Training failed ({code}); retain local data and inspect {log}')
    manifest = json.loads((output/'runs/rba/study.json').read_text())
    if manifest['status'] != 'COMPLETED':
        raise SystemExit(f'Not completed: {manifest["status"]}; inspect {log}')
    print('COMPLETED. Download results before ending this VM; Drive backup is DISABLED.', flush=True)
    from zipfile import ZipFile, ZIP_STORED
    archive = output.with_suffix('.zip')
    with ZipFile(archive, 'w', compression=ZIP_STORED) as zipfile:
        for path in output.rglob('*'):
            if path.is_file() and path.suffix not in ('.tmp','.copying'):
                zipfile.write(path, path.relative_to(output))
        zipfile.write(log, 'execution.log')
    from google.colab import files
    files.download(str(archive))


if __name__ == '__main__':
    main()
