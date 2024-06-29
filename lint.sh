#!/bin/bash

run_cargo_fmt() {
    MODE=$1
    if [ "$MODE" == "check" ]; then
        cargo fmt --all -- --check
    else
        cargo fmt --all
    fi
    return $?
}

run_cargo_clippy() {
    MODE=$1
    CMD="cargo clippy --all --all-targets --all-features"
    if [ "$MODE" == "fix" ]; then
        $CMD --fix --allow-staged --allow-dirty
    fi
    CMD="$CMD -- -D warnings"
    $CMD
    return $?
}

# Extract the mode from the argument
if [[ $1 == "--mode="* ]]; then
    MODE=${1#--mode=}
else
    echo "Please specify a mode with --mode=check or --mode=fix"
    exit 1
fi

# Run commands based on mode
case $MODE in
    check|fix)
        run_cargo_fmt $MODE
        FMT_EXIT_CODE=$?
        run_cargo_clippy $MODE
        CLIPPY_EXIT_CODE=$?

        ;;
    *)
        echo "Invalid mode. Please use --mode=check or --mode=fix"
        exit 1
        ;;
esac

# If any command failed, exit with a non-zero status code
if [ $FMT_EXIT_CODE -ne 0 ] || [ $CLIPPY_EXIT_CODE -ne 0 ]; then
    exit 1
fi