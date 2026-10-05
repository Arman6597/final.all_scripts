"""Модули run(send, baseline, **kwargs) и их адаптеры к GET-движку."""

from . import crlf, lfi, redirect, sqli, ssrf, ssti, xss

CHECKS = {'xss': xss.scan, 'lfi': lfi.scan, 'redirect': redirect.scan,
          'sqli': sqli.scan, 'ssrf': ssrf.scan, 'ssti': ssti.scan, 'crlf': crlf.scan}
