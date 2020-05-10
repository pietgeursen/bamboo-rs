# This script takes care of building your crate and packaging it for release

set -ex

main() {
    local src=$(pwd) \
          stage=

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    test -f Cargo.lock || cargo generate-lockfile

    if [ -z $IS_NO_STD ]
    then
      cd bamboo-cli
      cross build -p bamboo-cli --target $TARGET --release
      cd -
      cd bamboo-core
      cross build -p bamboo-core --target $TARGET --release
      cd -
    else
      cd bamboo-core
      cross build -p bamboo-core --target $TARGET --release --no-default-features
      cd -
    fi

    #strip target/$TARGET/release
    cp target/$TARGET/release/bamboo-cli $stage/ || true
    cp target/$TARGET/release/libbamboo_core.a $stage/
    cp target/$TARGET/release/libbamboo_core.so $stage/ || true

    cd $stage
    tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
    cd $src

    rm -rf $stage
}

main
