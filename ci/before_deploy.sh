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
      cross build --target $TARGET --release
      cp target/$TARGET/release/bamboo-cli $stage/
      cp target/$TARGET/release/libbamboo_core.a $stage/
      cp target/$TARGET/release/libbamboo_core.so $stage/
    else
      cd bamboo-core
      cross build -p bamboo-core --target $TARGET --release --no-default-features
      cp target/$TARGET/release/libbamboo_core.a $stage/
      cd ..
    fi

    #strip target/$TARGET/release

    cd $stage
    tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
    cd $src

    rm -rf $stage
}

main
