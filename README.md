# Vanity Pubky Generator

A tool for generating pubkys with custom prefixes.

## Overview

This tool allows you to create a vanity pubky that begins with a specific string of your choice. For example, you might want a public key that starts with your name or a meaningful word.

Every candidate key is derived from a 12-word English BIP39 recovery phrase in the same way as Pubky Ring. When a match is found, the program prints that phrase and also creates an encrypted recovery file.

### Single line usage
Just replace [PREFIX] with the desired prefix and [PASSPHRASE] with the desired passphrase.
```bash
git clone https://github.com/gcomte/vanity-pubky && cd vanity-pubky && cargo build --release && ./target/release/vanity-pubky [PREFIX] --passphrase [PASSPHRASE]
```

### Building from Source

1. Clone this repository or download the source code:
   ```bash
   git clone https://github.com/gcomte/vanity-pubky
    ```
2. Navigate to the project directory:
   ```bash
   cd vanity-pubky
   ```
3. Build the release version:
   ```bash
   cargo build --release
   ```
4. The executable will be available at `target/release/vanity-pubky` (or `target/release/vanity-pubky.exe` on Windows)

## Usage

Run the program with the following command:

```
./vanity-pubky [PREFIX] --passphrase [PASSPHRASE]
```

Where:
- `PREFIX` is the desired beginning letters of your public key
- `PASSPHRASE` is the passphrase used to encrypt the recovery file (default: "password")

### Examples

Generate a key that starts with "bob":
```
./vanity-pubky bob
```

Generate a key that starts with "bob" and provide your own passphrase:
```
./vanity-pubky bob --passphrase my_passphrase
```

## Output

The program will display:

1. The prefix it's searching for
2. The estimated average work for that prefix
3. The number of threads being used
4. Regular status updates showing the attempts made relative to the average
5. When a match is found:
    - The matching public key
    - The corresponding private key
    - A compatible 12-word recovery phrase
    - Number of attempts required
    - Time elapsed
    - Average search speed (keys/second)
6. The location of the saved recovery file

Each additional prefix character multiplies the average work by 32. A prefix of
length `n` therefore takes `32^n` attempts on average. This is a statistical
average, not a completion target: a search can finish much earlier or continue
past 100% of the average shown in progress updates.

## Recovery Files

When a matching key is found, the program automatically creates a recovery file with the naming pattern:
```
PREFIX_pubky_recovery.pkarr
```

This file is encrypted with the passphrase "password" unless another passphrase was specified.

## Recovery Phrases

The displayed recovery phrase is compatible with Pubky Ring: its standard BIP39 seed is derived with an empty BIP39 passphrase, and the first 32 bytes form the Pubky secret key. The `--passphrase` option only encrypts the `.pkarr` recovery file; it does not alter the 12-word phrase.

Keep the phrase private and store it securely. Anyone who has it controls the Pubky. The phrase is printed to the terminal but is not written to an unencrypted file.

Deriving each vanity candidate through BIP39 is intentionally more expensive than generating an arbitrary random key, so searches will be slower than in earlier releases.

## Building for Different Platforms

### For Windows
```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

### For macOS
```bash
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

### For Linux
```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```
