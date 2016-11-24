# This script was automatically generated from the dsa-1066
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22608);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1066");
 script_cve_id("CVE-2006-1896");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1066 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that phpbb2, a web based bulletin board, does
insufficiently sanitise values passed to the "Font Colour 3" setting,
which might lead to the execution of injected code by admin users.
The old stable distribution (woody) does not contain phpbb2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.13+1-6sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1066');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpbb2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1066] DSA-1066-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1066-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge3');
deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge3');
deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge3');
deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13+1-6sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
