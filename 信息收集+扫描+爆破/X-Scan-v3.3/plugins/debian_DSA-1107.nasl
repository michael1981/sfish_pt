# This script was automatically generated from the dsa-1107
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22649);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1107");
 script_cve_id("CVE-2006-3082");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1107 security update');
 script_set_attribute(attribute: 'description', value:
'Evgeny Legerov discovered that gnupg, the GNU privacy guard, a free
PGP replacement contains an integer overflow that can cause a
segmentation fault and possibly overwrite memory via a large user ID
string.
For the old stable distribution (woody) this problem has been fixed in
version 1.0.6-4woody6.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1.sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1107');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnupg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1107] DSA-1107-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1107-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody6');
deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
