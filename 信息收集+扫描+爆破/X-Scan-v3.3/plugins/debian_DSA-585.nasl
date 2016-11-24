# This script was automatically generated from the dsa-585
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15683);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "585");
 script_cve_id("CVE-2004-1001");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-585 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in the shadow suite which provides
programs like chfn and chsh.  It is possible for a user, who is logged
in but has an expired password to alter his account information with
chfn or chsh without having to change the password.  The problem was
originally thought to be more severe.
For the stable distribution (woody) this problem has been fixed in
version 20000902-12woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-585');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your passwd package (from the shadow
suite).');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA585] DSA-585-1 shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-585-1 shadow");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'login', release: '3.0', reference: '20000902-12woody1');
deb_check(prefix: 'passwd', release: '3.0', reference: '20000902-12woody1');
deb_check(prefix: 'shadow', release: '3.0', reference: '20000902-12woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
