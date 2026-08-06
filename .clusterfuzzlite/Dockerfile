FROM gcr.io/oss-fuzz-base/base-builder-rust
# The base image ships an older nightly (1.91.0-nightly as of 2026-08), while ainra-core declares
# rust-version = "1.96" — so `cargo fuzz build` failed with "rustc 1.91.0-nightly is not supported" and the
# fuzzers NEVER BUILT. A fuzzing job that cannot compile reports "failure", not "no crashes found", and this one
# had been reporting it every run. Update the nightly in the image rather than lowering the crate's floor: the
# floor is a real requirement, and cargo-fuzz needs a nightly for -Zsanitizer.
RUN rustup update nightly && rustup default nightly && rustc --version
COPY . $SRC/ainra
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/ainra
