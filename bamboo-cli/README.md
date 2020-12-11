# bamboo-cli

## Usage

### Help

`bamboo-cli --help`

### Generate a keypair

Maybe make a new dir to play around in. Then:

`$ bamboo-cli generate-keys --public-key-file pk --secret-key-file sk`

You can always get help for a subcommand like:

`$ bamboo-cli generate-keys --help`

Then you can check what your public key is as a hex string:

`$ xxd -p pk | tr -d '\n'`

Or as base64

`$ base64 pk`

### Publish the first entry

Create a new file called `payload_1` and write "hello world" in it. This is going to be the payload of our first entry in our feed.

Check the help for the publish command.

Then let's publish our first message:

`$ bamboo-cli publish --is-start-of-feed --public-key-file pk --secret-key-file sk --payload-file payload_1 > entry_1`

### Decode an entry so we can inspect it

`$ bamboo-cli decode entry_1`

### Verify an entry is valid

`$ bamboo-cli verify --entry-file entry_1 --payload-file payload_1`

Note that you can omit the payload if you want. This is part of supporting offchain content.

### Publish new entries

This is slightly more complicated because we need to calculate the lipmaa number for the entry we're publishing.

If we want to publish the second entry, then calculate the lipmaa number like:

`$ bamboo-cli lipmaa 2`

And you should get 1.

So the lipmaa entry in this case will be entry_1

Try out publishing a new entry. You'll have to provide the `--lipmaa-entry-file` and the `--previous-entry-file` arguments this time.

You can run `$ bamboo-cli hash entry_1 | xxd -p` and `$ bamboo-cli hash payload_1 | xxd -p` to calculate the hashes and print them as a hex string. You can decode entry_2 and see that the entry_2 backlink value is the same as `$ bamboo-cli hash entry_1 | xxd -p`.

### Bonus fun: Post an entry to a "pub".

Go here: https://mighty-sands-24362.herokuapp.com/swagger/index.html

This is from https://github.com/pietgeursen/bamboo-rest-api which is deployed to Heroku.

Select the `POST /` route in swagger, then `Try It Out`

Encode your first entry as a hex string:

`$ xxd -p entry_1 | tr -d '\n'`

And copy the result **without any weird trailing characters your terminal might print eg '%'**

Paste it into swagger as the `encodedEntry`

Now do the same for the payload.

Hit `Execute`. If that went ok, you should get a 200.

Now if you hit `GET /` in swagger you should see your public key as one of the authors in the array.
