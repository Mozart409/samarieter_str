set dotenv-load

default:
	just --choose

dev:
	cargo watch -q -c -x run

fix: clear rfmt dprint

rfmt: 
	cargo +nightly run fmt

dprint: clear
	dprint fmt

clear:
	clear