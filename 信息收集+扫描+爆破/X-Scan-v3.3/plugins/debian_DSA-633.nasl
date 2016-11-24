# This script was automatically generated from the dsa-633
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16130);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "633");
 script_cve_id("CVE-2003-0014");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-633 security update');
 script_set_attribute(attribute: 'description', value:
'Peter Samuelson, upstream maintainer of bmv, a PostScript viewer for
SVGAlib, discovered that temporary files are created in an insecure
fashion.  A malicious local user could cause arbitrary files to be
overwritten by a symlink attack.
For the stable distribution (woody) this problem has been
fixed in version 1.2-14.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-633');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bmv packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA633] DSA-633-1 bmv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-633-1 bmv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bmv', release: '3.0', reference: '1.2-14.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
