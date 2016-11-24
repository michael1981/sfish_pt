# This script was automatically generated from the dsa-421
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15258);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "421");
 script_cve_id("CVE-2004-0041");
 script_bugtraq_id(9404);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-421 security update');
 script_set_attribute(attribute: 'description', value:
'David B Harris discovered a problem with mod-auth-shadow, an Apache
module which authenticates users against the system shadow password
database, where the expiration status of the user\'s account and
password were not enforced.  This vulnerability would allow an
otherwise authorized user to successfully authenticate, when the
attempt should be rejected due to the expiration parameters.
For the current stable distribution (woody) this problem has been
fixed in version 1.3-3.1woody.1
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-421');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-421
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA421] DSA-421-1 mod-auth-shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-421-1 mod-auth-shadow");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
