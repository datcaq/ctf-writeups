"""Run the three Typhone cryptanalysis stages against the bundled instance."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent
    env = dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    for script in ('solve_typhon.py', 'boneh_durfee.py', 'coppersmith_partial_factor.py'):
        print(f'\n=== {script} ===', flush=True)
        subprocess.run([sys.executable, str(root / script)], cwd=root, env=env, check=True)


if __name__ == '__main__':
    main()
