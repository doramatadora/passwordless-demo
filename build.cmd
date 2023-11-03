for /f "tokens=1* delims==" %%A in (.env) do (
    set "%%A=%%B"
)
js-compute-runtime bin/index.js bin/main.wasm
