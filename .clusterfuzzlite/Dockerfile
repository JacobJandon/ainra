FROM gcr.io/oss-fuzz-base/base-builder-rust
# The base image ships an older nightly (1.91.0-nightly) than ainra-core's declared rust-version = "1.96", so
# `cargo fuzz build` failed with "rustc 1.91.0-nightly is not supported" and the fuzzers NEVER BUILT — the job had
# been reporting "failure" every run, which reads as "fuzzing found something" when it meant "fuzzing never ran".
#
# `rustup update nightly` alone is NOT enough: it installs 1.99 but the image pins the toolchain through the
# RUSTUP_TOOLCHAIN environment variable, which overrides `rustup default`, so rustc still resolved to 1.91.
# Both are needed — the install and the override.
RUN rustup update nightly
ENV RUSTUP_TOOLCHAIN=nightly
RUN rustc --version
COPY . $SRC/ainra
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/ainra
