# This script takes care of testing your crate

set -ex

main() {
    if [ ! -z $IS_NO_STD ] 
    then
      cd bamboo-core
      cross build -p bamboo-core --target $TARGET --release --no-default-features
      return
    fi

    cross build --target $TARGET

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET

    # Try and the binary
    cross run --bin bamboo-cli --target $TARGET -- --help
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
