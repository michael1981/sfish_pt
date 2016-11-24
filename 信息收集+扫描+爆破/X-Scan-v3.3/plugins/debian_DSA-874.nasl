# This script was automatically generated from the dsa-874
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22740);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "874");
 script_cve_id("CVE-2005-3120");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-874 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered a buffer overflow in lynx, a text-mode
browser for the WWW that can be remotely exploited.  During the
handling of Asian characters when connecting to an NNTP server lynx
can be tricked to write past the boundary of a buffer which can lead
to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.4.1b-3.3.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.5-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-874');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lynx package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA874] DSA-874-1 lynx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-874-1 lynx");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lynx', release: '3.0', reference: '2.8.4.1b-3.3');
deb_check(prefix: 'lynx', release: '3.1', reference: '2.8.5-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
