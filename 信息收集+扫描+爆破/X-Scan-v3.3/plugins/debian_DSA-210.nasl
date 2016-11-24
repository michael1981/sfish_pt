# This script was automatically generated from the dsa-210
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15047);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "210");
 script_cve_id("CVE-2002-1405");
 script_bugtraq_id(5499);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-210 security update');
 script_set_attribute(attribute: 'description', value:
'lynx (a text-only web browser) did not properly check for illegal
characters in all places, including processing of command line options,
which could be used to insert extra HTTP headers in a request.
For Debian GNU/Linux 2.2/potato this has been fixed in version 2.8.3-1.1
of the lynx package and version 2.8.3.1-1.1 of the lynx-ssl package.
For Debian GNU/Linux 3.0/woody this has been fixed in version 2.8.4.1b-3.2
of the lynx package and version 1:2.8.4.1b-3.1 of the lynx-ssl package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-210');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-210
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA210] DSA-210-1 lynx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-210-1 lynx");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lynx', release: '2.2', reference: '2.8.3-1.1');
deb_check(prefix: 'lynx-ssl', release: '2.2', reference: '2.8.3.1-1.1');
deb_check(prefix: 'lynx', release: '3.0', reference: '2.8.4.1b-3.2');
deb_check(prefix: 'lynx-ssl', release: '3.0', reference: '2.8.4.1b-3.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
