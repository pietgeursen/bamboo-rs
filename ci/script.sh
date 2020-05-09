# This script takes care of testing your crate

set -ex

main() {
    cross build --target $TARGET

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET

    # Try and the binary
    cross run --bin bamboo-cli --target $TARGET -- --help
    cd bamboo-cli/test_script/
    ./test.sh
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
