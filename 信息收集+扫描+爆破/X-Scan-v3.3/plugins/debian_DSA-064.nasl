# This script was automatically generated from the dsa-064
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14901);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "064");
 script_cve_id("CVE-2001-0700");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-064 security update');
 script_set_attribute(attribute: 'description', value:
'SecureNet Service reported that w3m (a console web browser) has a
buffer overflow in its MIME header parsing code. This could be exploited
by an attacker if by making a web-server a user visits return carefully
crafted MIME headers.

This has been fixed in version 0.1.10+0.1.11pre+kokb23-4, and we
recommend that you upgrade your w3m package.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-064');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-064
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA064] DSA-064-1 w3m");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-064-1 w3m");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'w3m', release: '2.2', reference: '0.1.10+0.1.11pre+kokb23-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
