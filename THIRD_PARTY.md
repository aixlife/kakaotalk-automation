# Reader implementation references

Codec-context discovery was adapted conceptually from [is-theo/kakao-cli-win at revision 411d0dd1b472ea8a0cc8bf399e3351c0651748b6](https://github.com/is-theo/kakao-cli-win/blob/411d0dd1b472ea8a0cc8bf399e3351c0651748b6/kwin/cli.py). This prototype uses 64-bit pointers, bounded streaming reads, DB-page HMAC validation, and process-only key/plaintext lifetime. It does not run the upstream CLI, preserve memory regions, write key JSON, start its web server, or export all rooms.

SQLCipher layout and page authentication were checked against [upstream SQLCipher](https://github.com/sqlcipher/sqlcipher/blob/master/src/sqlcipher.c). The upstream master version may differ from the installed app; successful database-page authentication is required before accepting a candidate.

The x86 adapter is a bounded, unproven MSVC object-layout candidate. It is not an extracted implementation or a claim that the protected x86 native function offsets have been established. It requires IKM AES-KW, selected database-key AES-KW, and SQLCipher authentication before accepting a candidate. KakaoTalk installers and executable files are not distributed in this repository.

## APSW dependency — 3.54.1.0

The large-database reader uses [APSW](https://rogerbinns.github.io/apsw/) for a read-only SQLite VFS. APSW is installed as a pinned dependency, not copied into this repository. Its [versioned license](https://github.com/rogerbinns/apsw/blob/3.54.1.0/LICENSE) states:

Copyright (c) 2004-2026 Roger Binns <rogerb@rogerbinns.com>

All code and documentation is provided under this license:

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source
   distribution.

Alternatively you may strike the license above and use it under any
OSI approved open source license such as those listed at
https://opensource.org/licenses/alphabetical

SPDX-License-Identifier: any-OSI

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
