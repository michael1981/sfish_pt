# This script was automatically generated from the dsa-414
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15251);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "414");
 script_cve_id("CVE-2004-0013");
 script_bugtraq_id(9376);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-414 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in jabber, an instant messaging server,
whereby a bug in the handling of SSL connections could cause the
server process to crash, resulting in a denial of service.
For the current stable distribution (woody) this problem has been
fixed in version 1.4.2a-1.1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-414');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-414
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA414] DSA-414-1 jabber");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-414-1 jabber");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'jabber', release: '3.0', reference: '1.4.2a-1.1woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
