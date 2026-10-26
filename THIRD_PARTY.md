# Reader implementation references

Codec-context discovery was adapted conceptually from [is-theo/kakao-cli-win at revision 411d0dd1b472ea8a0cc8bf399e3351c0651748b6](https://github.com/is-theo/kakao-cli-win/blob/411d0dd1b472ea8a0cc8bf399e3351c0651748b6/kwin/cli.py). This prototype uses 64-bit pointers, bounded streaming reads, DB-page HMAC validation, and process-only key/plaintext lifetime. It does not run the upstream CLI, preserve memory regions, write key JSON, start its web server, or export all rooms.

SQLCipher layout and page authentication were checked against [upstream SQLCipher](https://github.com/sqlcipher/sqlcipher/blob/master/src/sqlcipher.c). The upstream master version may differ from the installed app; successful database-page authentication is required before accepting a candidate.

## MIT License — referenced Windows implementation

Copyright (c) 2026 theo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## MIT License — referenced Mac skill

The Mac command workflow and original skill name refer to [NomaDamas/k-skill](https://github.com/NomaDamas/k-skill). Its upstream LICENSE records the following notice without an author name:

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
