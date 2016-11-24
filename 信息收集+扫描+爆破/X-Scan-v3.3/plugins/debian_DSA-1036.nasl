# This script was automatically generated from the dsa-1036
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22578);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1036");
 script_cve_id("CVE-2006-1744");
 script_bugtraq_id(17401);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1036 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow problem has been discovered in sail, a game contained
in the bsdgames package, a collection of classic textual Unix games, which
could lead to games group privilege escalation.
For the old stable distribution (woody) this problem has been fixed in
version 2.13-7woody0.
For the stable distribution (sarge) this problem has been fixed in
version 2.17-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1036');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bsdgames package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1036] DSA-1036-1 bsdgames");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1036-1 bsdgames");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bsdgames', release: '3.0', reference: '2.13-7woody0');
deb_check(prefix: 'bsdgames', release: '3.1', reference: '2.17-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
