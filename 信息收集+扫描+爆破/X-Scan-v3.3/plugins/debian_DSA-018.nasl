# This script was automatically generated from the dsa-018
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14855);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "018");
 script_cve_id("CVE-2001-0129");
 script_bugtraq_id(2217);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-018 security update');
 script_set_attribute(attribute: 'description', value:
'PkC have found a heap overflow in tinyproxy that could be remotely exploited.  An attacker could gain a shell (user nobody) remotely.

We recommend you upgrade your tinyproxy package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-018');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-018
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA018] DSA-018-1 tinyproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-018-1 tinyproxy");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tinyproxy', release: '2.2', reference: '1.3.1-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
