format:
	poetry run black .
	poetry run isort .

lint:
	poetry run flake8 .
	poetry run mypy .

check: format lint

pre-commit:
	poetry run pre-commit run --all-files

quality: format lint pre-commit

clean:
	rm -rf dist/ build/ *.egg-info/

build: clean
	python -m build

test-publish: build
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

publish: build
	twine upload dist/*
