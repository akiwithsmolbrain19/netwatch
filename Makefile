.PHONY: test lint security check demo

test:
	python3 -m pytest tests/ -q

lint:
	python3 -m py_compile $$(git ls-files '*.py')

security:
	grep -rniE 'aws_secret|BEGIN [A-Z ]*PRIVATE KEY|password\s*=\s*["'\''][^"'\'']+["'\'']' --include='*.py' --include='*.yaml' --include='*.md' . | grep -v sample_data || true
	python3 -c "import yaml" 2>/dev/null && python3 -c "import yaml; yaml.safe_load(open('config/default.yaml')); print('config parses OK')" || python3 -c "print('pyyaml not installed; config check skipped')"

check: test lint security

demo:
	python3 -m netwatch.cli --help
	python3 scripts/gen_samples.py --help 2>/dev/null || true
