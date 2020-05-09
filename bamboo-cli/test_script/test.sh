cargo build --release &&
cp ../../target/release/bamboo-cli . &&

echo "Generate keys" &&
./bamboo-cli generate-keys --public-key-file pk --secret-key-file sk &&

echo "Publish first entry" &&
./bamboo-cli publish --is-start-of-feed --public-key-file pk --secret-key-file sk --payload-file bamboo-cli > entry_1 &&

echo "Publish second entry" &&
./bamboo-cli publish --lipmaa-entry-file entry_1 --previous-entry-file entry_1 --public-key-file pk --secret-key-file sk --payload-file bamboo-cli > entry_2 &&

echo "Verfiy entry 1 with payload" &&
./bamboo-cli verify --entry-file entry_1 --payload-file bamboo-cli &&
echo "Verfiy entry 1 without payload" &&
./bamboo-cli verify --entry-file entry_1 &&

echo "Verfiy entry 2 with payload" &&
./bamboo-cli verify --entry-file entry_2 --lipmaa-entry-file entry_1 --previous-entry-file entry_1 --payload-file bamboo-cli &&
echo "Verfiy entry 2 without payload" &&
./bamboo-cli verify --entry-file entry_2 --lipmaa-entry-file entry_1 --previous-entry-file entry_1 &&

echo "All g"
