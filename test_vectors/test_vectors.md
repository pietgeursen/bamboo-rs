# Test Vectors 

> [Vectors](./test_vectors.json) for testing your own implementation of bamboo

## Byte encodings in the json.

Binary representations are stored as lower case base16 (hexadecimal) strings.

If the json looked like this: 

```json
{
  "encoded": "00014069db5208a271c53de8a1b6220e6a4d7fcccd89e6c0c7e75c833e34dc68d932624f2ccf27513f42fb7d0e4390a99b225bad41ba14a6297537246dbe4e6ce150e80d0120b46f22fbd233f30af255294701f96b9fd89220588cdbbb42150164a451e9b11101403e39afaabde37ff1eea5078e3c055c74099102ec1ca6971045ad25f801fd1e7b446bf9b6988f4dce30e5f04b554a6736878e3d2964af0773c78638e84ad20200"
}
```

then in node.js you could do this to parse the bytes into a Buffer:

```js

const {encoded} = require('./<...>')

const buff = Buffer.from(encoded, 'hex')

```

## Vectors

### A valid first entry

A good place to start is with a valid first entry in a bamboo chain.

- key: validFirstEntry
- payload: "hello bamboo!" 

Json structure:

```js
{
  validFirstEntry: {
    description: "..."
    decoded: {
      "author": {
        "Ed25519": [
          "<hex_bytes>"
        ]
      },
        "backlink": null,
        "isEndOfFeed": false,
        "lipmaaLink": null,
        "payloadHash": {
          "Blake2b": "<hex_bytes>"
        },
        "payloadSize": 16,
        "seqNum": 1,
        "signature": "<hex_bytes>"
    },
    encoded: "<hex_bytes>"
    payload: "hello bamboo!"
  }
}
```
