# This script was automatically generated from the dsa-195
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15032);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "195");
 script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
 script_bugtraq_id(5847, 5884, 5887, 5995);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-195 security update');
 script_set_attribute(attribute: 'description', value:
'According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several vulnerabilities have been found in the Apache server
package, a commonly used webserver.  Most of the code is shared
between the Apache and Apache-Perl packages, so vulnerabilities are
shared as well.
These vulnerabilities could allow an attacker to enact a denial of
service against a server or execute a cross site scripting attack, or
steal cookies from other web site users.  The Common Vulnerabilities
and Exposures (CVE) project identified the following vulnerabilities:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-195');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Apache-Perl package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA195] DSA-195-1 apache-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-195-1 apache-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache-perl', release: '2.2', reference: '1.3.9-14.1-1.21.20000309-1.1');
deb_check(prefix: 'apache-perl', release: '3.0', reference: '1.3.26-1-1.26-0woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
