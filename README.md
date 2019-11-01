# GOga - Recover function names from Go binary

GOga.py is an IDA Pro script used to recover function names from Go binaries. It extracts the metadata present in ```.gopclntab``` segment. It also tells the Go version used to build the binary by finding the version string from binary. Meaningful comments have been added in the code to make it easier to understand.

## Usage

Load the Go binary in IDA pro

```
File  ->  Script File  -> Select GOga.py
```

## Sample

### Before

![Image not found](https://raw.githubusercontent.com/r0hanSH/GOga/master/sample/screenshots/before.JPG)

### After

![Image not found](https://raw.githubusercontent.com/r0hanSH/GOga/master/sample/screenshots/after.JPG)


## TODO list

Once I finish my other projects, I will add types and string recovery code in ```GOga```