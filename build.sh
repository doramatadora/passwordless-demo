export $(xargs < .env) 2>/dev/null
js-compute-runtime bin/index.js bin/main.wasm
