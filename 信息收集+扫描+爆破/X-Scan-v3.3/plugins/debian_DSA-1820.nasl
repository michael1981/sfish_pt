# This script was automatically generated from the dsa-1820
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39452);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1820");
 script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1820 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2009-1392
Several issues in the browser engine have been discovered, which can
result in the execution of arbitrary code. (MFSA 2009-24)
CVE-2009-1832
It is possible to execute arbitrary code via vectors involving "double
frame construction." (MFSA 2009-24)
CVE-2009-1833
Jesse Ruderman and Adam Hauner discovered a problem in the JavaScript
engine, which could lead to the execution of arbitrary code.
(MFSA 2009-24)
CVE-2009-1834
Pavel Cvrcek discovered a potential issue leading to a spoofing attack
on the location bar related to certain invalid unicode characters.
(MFSA 2009-25)
CVE-2009-1835
Gregory Fleischer discovered that it is possible to read arbitrary
cookies via a crafted HTML document. (MFSA 2009-26)
CVE-2009-1836
Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang reported a potential
man-in-the-middle attack, when using a proxy due to insufficient checks
on a certain proxy response. (MFSA 2009-27)
CVE-2009-1837
Jakob Balle and Carsten Eiram reported a race condition in the
NPObjWrapper_NewResolve function that can be used to execute arbitrary
code. (MFSA 2009-28)
CVE-2009-1838
moz_bug_r_a4 discovered that it is possible to execute arbitrary
JavaScript with chrome privileges due to an error in the
garbage-collection implementation. (MFSA 2009-29)
CVE-2009-1839
Adam Barth and Collin Jackson reported a potential privilege escalation
when loading a file::resource via the location bar. (MFSA 2009-30)
CVE-2009-1840
Wladimir Palant discovered that it is possible to bypass access
restrictions due to a lack of content policy check, when loading a
script file into a XUL document. (MFSA 2009-31)
CVE-2009-1841
moz_bug_r_a4 reported that it is possible for scripts from page content
to run with elevated privileges and thus potentially executing arbitrary
code with the object\'s chrome privileges. (MFSA 2009-32)
For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.11-0lenny1.
As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1820');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1820] DSA-1820-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1820-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmozillainterfaces-java', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'libmozjs-dev', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'libmozjs1d', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'libmozjs1d-dbg', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'python-xpcom', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'spidermonkey-bin', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'xulrunner-1.9', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'xulrunner-1.9-dbg', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'xulrunner-1.9-gnome-support', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'xulrunner-dev', release: '5.0', reference: '1.9.0.11-0lenny1');
deb_check(prefix: 'xulrunner', release: '5.0', reference: '1.9.0.11-0lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
