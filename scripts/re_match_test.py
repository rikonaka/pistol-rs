import re


test_str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
pattern = '^SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Ubuntu[ -_]([^\r\n]+)\r?\n'
prog = re.compile(pattern)
result = prog.match(test_str)
print(result)


test_str = "HTTP/1.1 200 OK\r\nDate: Sun, 28 Apr 2024 13:42:24 GMT\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
pattern = "^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[-.\w]+) ([^\r\n]+)/s"
pattern = "^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache[/ ](\d[.\w-]+)\s*\r?\n/s"
pattern = "^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: Apache +\(([^\r\n\)]+)\)\r\n/s"
prog = re.compile(pattern)
result = prog.match(test_str)
print(result)

# test_str = 'HTTP/1.1 200 OK\r\nDate: Sun, 28 Apr 2024 13:42:24 GMT\r\nServer: Apache/2.4.52 (Ubuntu)\r\n'
# test_str = 'HTTP/1.1 200 OK\r\nDate: Sun, 28 Apr 2024 13:42:24 GMT\r\nServer: Apache/2.4.52 (Ubuntu)\r\nLast-Modified: Sun, 28 Apr 2024 04:52:36 GMT\r\nETag: "29af-61720e7d531b3"\r\nAccept-Ranges: bytes\r\nContent-Length: 10671\r\nVary: Accept-Encoding\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n'
#
# pattern = '^HTTP/1\.[01] (.*?400)\d\d\d.*\r\nDate: .*\r\nServer: Apache ([^\r\n]+)\r\n'
# prog = re.compile(pattern)
# result = prog.match(test_str)
# print(result)
#
# pattern = '^HTTP/1\.[01] \d\d\d.*\r\nDate: .*\r\nServer: Apache ((?:[\w_]+/[\w._-]+ ?)+)\r\n'
# prog = re.compile(pattern)
# result = prog.match(test_str)
# print(result)
#
# pattern = '^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(.*?\r\n))*?Server: Apache +\(([^\r\n\)]+)\)\r\n'
# prog = re.compile(pattern)
# result = prog.match(test_str)
# print(result)
#
# pattern = '^HTTP/1\.[01] \d\d\d.*\r\nDate: .*\r\nServer: Apache'
# prog = re.compile(pattern)
# result = prog.match(test_str)
# print(result)
