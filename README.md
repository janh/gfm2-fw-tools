# Glasfaser-Modem 2 Firmware Tools

With these Python scripts it is possible to deconstruct a firmware image, and also construct it again.

You can start by decrypting the image:

```
python decrypt.py firmware.img decrypted.bin
```

Now continue by decompressing this file:

```
python decompress.py decrypted.bin decompressed.bin
```

This will also create an additional file named "decomressed.bin.pid" containing the PID from the header.

Finally, unpack the individual partition images:

```
python unpack.py decompressed.bin unpacked
```

The firmware is likely to contain a separate "rootfs" and "lib" image.
They will be stored in a new folder called "unpacked", along with some metadata from the header (including the signature).

To reconstruct the firmware image again, just do the reverse:

```
python pack.py unpacked decompressed.bin
python compress.py decompressed.bin decrypted.bin
python encrypt.py decrypted.bin firmware.img
```

The scripts are designed to produce identical output to the original where possible.
However, the final encrypted image still differs, because the IV and salt used for the encryption are generated randomly.

Note that you cannot modify the actual partition images, as that would invalidate the signature.
What might work is to reconstruct a firmware image based on dumped partitions from a device, but this is untested.

For some information about the image formats, take a look at the comments in the file "common.py".
