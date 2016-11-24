== Changelog
============

0.7
	- Added system,S flag that makes gsecdump elevate to localsystem (if not already) by creating a service and running itself through it. This was added after feedback from Jonas Ländin.
	- Dropped error message when gsecdump fails to enumerate password history entries. The Microsoft RODCs (Read-Only DC) don't support history entries so you get an error all the time on these DCs. Annoying. Besides, if I can't get history entires I accept that I can't get them, no reason crying about it. If I'm way of here, give me feedback and I'll add some verbose flag or something. This was fixed after feedback from Christoffer Andersson.

== README
=========

To build gsecdump you need boost libraries from http://www.boost.org.
