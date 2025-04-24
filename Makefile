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
