# This script was automatically generated from the dsa-250
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15087);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "250");
 script_cve_id("CVE-2002-1335", "CVE-2002-1348");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-250 security update');
 script_set_attribute(attribute: 'description', value:
'Hironori Sakamoto, one of the w3m developers, found two security
vulnerabilities in w3m and associated programs.  The w3m browser does
not properly escape HTML tags in frame contents and img alt
attributes.  A malicious HTML frame or img alt attribute may deceive a
user to send their local cookies which are used for configuration.  The
information is not leaked automatically, though.
For the stable distribution (woody) these problems have been fixed in
version 0.3.p23.3-1.5.  Please note that the update also contains an
important patch to make the program work on the powerpc platform again.
The old stable distribution (potato) is not affected by these
problems.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-250');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your w3mmee-ssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA250] DSA-250-1 w3mmee-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-250-1 w3mmee-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'w3mmee-ssl', release: '3.0', reference: '0.3.p23.3-1.5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
