#!/usr/bin/env bash
# Script for building your rust projects.
set -e

source ci/common.bash

# $1 {path} = Path to cross/cargo executable
CROSS=$1
# $1 {string} = <Target Triple> e.g. x86_64-pc-windows-msvc
TARGET_TRIPLE=$2
# $3 {boolean} = Are we building for deployment? 
RELEASE_BUILD=$3
# $4 {boolean} = Are we building for no-std? 
NO_STD=$4

required_arg $CROSS 'CROSS'
required_arg $TARGET_TRIPLE '<Target Triple>'

if [ -z "$RELEASE_BUILD" ]; then
    if [ -z $NO_STD ]
    then
      $CROSS build --target $TARGET_TRIPLE
      $CROSS build --target $TARGET_TRIPLE --all-features
    else
      mkdir -p target/$TARGET_TRIPLE/debug 
      cd bamboo-rs-core
      $CROSS build -p bamboo-rs-core --target $TARGET_TRIPLE --no-default-features
      cp target/$TARGET_TRIPLE/debug/libbamboo_rs_core.a ../target/$TARGET_TRIPLE/debug
      cd ..
    fi
else
    if [ -z $NO_STD ]
    then
      $CROSS build --target $TARGET_TRIPLE --all-features --release
    else
      mkdir -p target/$TARGET_TRIPLE/release 
      cd bamboo-rs-core
      $CROSS build -p bamboo-rs-core --target $TARGET_TRIPLE --release --no-default-features
      cp target/$TARGET_TRIPLE/release/libbamboo_rs_core.a ../target/$TARGET_TRIPLE/release
      cd ..
    fi
fi

