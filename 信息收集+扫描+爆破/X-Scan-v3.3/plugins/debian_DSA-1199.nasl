# This script was automatically generated from the dsa-1199
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22908);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1199");
 script_cve_id("CVE-2005-3912", "CVE-2006-3392", "CVE-2006-4542");
 script_bugtraq_id(15629, 18744, 19820);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1199 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been identified in webmin, a web-based
administration toolkit. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
CVE-2005-3912
	A format string vulnerability in miniserv.pl could allow an
	attacker to cause a denial of service by crashing the
	application or exhausting system resources, and could
	potentially allow arbitrary code execution.
CVE-2006-3392
	Improper input sanitization in miniserv.pl could allow an
	attacker to read arbitrary files on the webmin host by providing
	a specially crafted URL path to the miniserv http server.
CVE-2006-4542
	Improper handling of null characters in URLs in miniserv.pl
	could allow an attacker to conduct cross-site scripting attacks,
	read CGI program source code, list local directories, and
	potentially execute arbitrary code.
Stable updates are available for alpha, amd64, arm, hppa, i386, ia64,
m68k, mips, mipsel, powerpc, s390 and sparc.
For the stable distribution (sarge), these problems have been fixed in
version 1.180-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1199');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webmin (1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1199] DSA-1199-1 webmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1199-1 webmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webmin', release: '3.1', reference: '1.180-3sarge1');
deb_check(prefix: 'webmin-core', release: '3.1', reference: '1.180-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
