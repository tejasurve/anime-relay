import subprocess

p = subprocess.run(['node', 'test_eval.js'], capture_output=True, text=True)
with open('res.txt', 'w') as f:
    f.write("STDOUT:\n" + p.stdout + "\nSTDERR:\n" + p.stderr)
