.PHONY: setup format check build

setup:
	npm ci

format:
	npm run format

check:
	npm run check

build:
	npm run build
