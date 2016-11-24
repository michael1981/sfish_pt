# This script was automatically generated from the dsa-436
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15273);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "436");
 script_cve_id("CVE-2003-0038", "CVE-2003-0965", "CVE-2003-0991");
 script_bugtraq_id(9336, 9620);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-436 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been fixed in the mailman package:
The cross-site scripting vulnerabilities could allow an attacker to
perform administrative operations without authorization, by stealing a
session cookie.
For the current stable distribution (woody) these problems have been
fixed in version 2.0.11-1woody7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-436');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-436
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA436] DSA-436-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-436-1 mailman");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody8');
deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
