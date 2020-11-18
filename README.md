## webadb

ADB (Android Debug Bridge) implementation on WebUSB written in Rust

### Build

```sh
RUSTFLAGS=--cfg=web_sys_unstable_apis wasm-pack build --target web
```

## License

MIT