# Getting set up with Rust
This is a one time set-up for your Rust environment

Install Rust via [rustup](https://rustup.rs/)
```sh
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Add WASI build target
```sh
$ rustup target add wasm32-wasip1
```

Install `cmake`. This enables builds targeting your local machine which will enable intellisense.
```sh
$ brew install cmake
```

If you are using VSCode, install the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) plugin for intellisense support
