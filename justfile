set dotenv-load

default:
	cargo watch -q -c -x run

fmt: clear
	cargo +nightly run fmt

clear:
	clear