# This script was automatically generated from the dsa-321
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15158);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "321");
 script_cve_id("CVE-2003-0450");
 script_bugtraq_id(7892);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-321 security update');
 script_set_attribute(attribute: 'description', value:
'radiusd-cistron contains a bug allowing a buffer overflow when a long
NAS-Port attribute is received.  This could allow a remote attacker to
execute arbitrary code on the server with the privileges of the RADIUS daemon
(usually root).
For the stable distribution (woody) this problem has been fixed in
version 1.6.6-1woody1.
For the old stable distribution (potato), this problem will be fixed
in a later advisory.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-321');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-321
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA321] DSA-321-1 radiusd-cistron");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-321-1 radiusd-cistron");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'radiusd-cistron', release: '3.0', reference: '1.6.6-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
