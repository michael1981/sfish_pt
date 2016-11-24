# This script was automatically generated from the dsa-132
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14969);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "132");
 script_cve_id("CVE-2002-0392");
 script_bugtraq_id(5033);
 script_xref(name: "CERT", value: "944335");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-132 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Litchfield found a denial of service attack in the Apache
web-server. While investigating the problem the Apache Software
Foundation discovered that the code for handling invalid requests which
use chunked encoding also might allow arbitrary code execution on 64 bit
architectures.
This has been fixed in version 1.3.9.13-4.1 of the Debian apache-ssl
package and we recommend that you upgrade your apache-ssl package
immediately.
An update for the soon to be released Debian GNU/Linux 3.0/woody
distribution is not available at the moment.
More Information:
CVE-2002-0392,
VU#944335.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-132');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-132
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA132] DSA-132-1 apache-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-132-1 apache-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-4.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
