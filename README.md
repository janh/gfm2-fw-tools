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

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
