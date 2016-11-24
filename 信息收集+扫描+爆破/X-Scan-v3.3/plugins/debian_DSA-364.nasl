# This script was automatically generated from the dsa-364
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15201);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "364");
 script_cve_id("CVE-2003-0620", "CVE-2003-0645");
 script_bugtraq_id(8303, 8341);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-364 security update');
 script_set_attribute(attribute: 'description', value:
'man-db provides the standard man(1) command on Debian systems.  During
configuration of this package, the administrator is asked whether
man(1) should run setuid to a dedicated user ("man") in order to
provide a shared cache of preformatted manual pages.  The default is
for man(1) NOT to be setuid, and in this configuration no known
vulnerability exists.  However, if the user explicitly requests setuid
operation, a local attacker could exploit either of the following bugs to
execute arbitrary code as the "man" user.
Again, these vulnerabilities do not affect the default configuration,
where man is not setuid.
For the current stable distribution (woody), these problems have been
fixed in version 2.3.20-18.woody.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-364');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-364
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA364] DSA-364-3 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-364-3 man-db");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'man-db', release: '3.0', reference: '2.3.20-18.woody.4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
