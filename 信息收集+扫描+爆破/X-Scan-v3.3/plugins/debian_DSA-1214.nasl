# This script was automatically generated from the dsa-1214
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23700);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1214");
 script_cve_id("CVE-2006-5864");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1214 security update');
 script_set_attribute(attribute: 'description', value:
'The original update provided in DSA 1214-1 was insufficient; this update
corrects this. For reference please find the original advisory text below:

Renaud Lifchitz discovered that gv, the PostScript and PDF viewer for X,
performs insufficient boundary checks in the Postscript parsing code,
which allows the execution of arbitrary code through a buffer overflow.
For the stable distribution (sarge) this problem has been fixed in
version 3.6.1-10sarge2.
For the upcoming stable distribution (etch) this problem has been
fixed in version 3.6.2-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1214');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gv package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1214] DSA-1214-2 gv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1214-2 gv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gv', release: '3.1', reference: '3.6.1-10sarge2');
deb_check(prefix: 'gv', release: '4.0', reference: '3.6.2-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
