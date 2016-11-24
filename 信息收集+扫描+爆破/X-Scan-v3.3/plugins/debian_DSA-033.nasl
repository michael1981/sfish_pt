# This script was automatically generated from the dsa-033
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14870);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "033");
 script_cve_id("CVE-2001-0301");
 script_bugtraq_id(2377);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-033 security update');
 script_set_attribute(attribute: 'description', value:
'The author of analog, Stephen Turner, has found a buffer
overflow bug in all versions of analog except of version 4.16.  A malicious
user could use an ALIAS command to construct very long strings which were not
checked for length and boundaries.  This bug is particularly dangerous if the
form interface (which allows unknown users to run the program via a CGI script)
has been installed.  There doesn\'t seem to be a known exploit.

The bugfix has been backported to the version of analog from Debian
2.2.  Version 4.01-1potato1 is fixed.

We recommend you upgrade your analog packages immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-033');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-033
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA033] DSA-033-1 analog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-033-1 analog");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'analog', release: '2.2', reference: '4.01-1potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
