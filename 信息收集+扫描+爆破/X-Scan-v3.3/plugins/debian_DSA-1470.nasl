# This script was automatically generated from the dsa-1470
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30062);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1470");
 script_cve_id("CVE-2007-6018");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1470 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf H&auml;rnhammar discovered that the HTML filter of the Horde web
application framework performed insufficient input sanitising, which
may lead to the deletion of emails if a user is tricked into viewing
a malformed email inside the Imp client.
This update also provides backported bugfixes to the cross-site 
scripting filter and the user management API from the latest Horde
release 3.1.6.
The old stable distribution (sarge) is not affected. An update to
Etch is recommended, though.
For the stable distribution (etch), this problem has been fixed in
version 3.1.3-4etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1470');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1470] DSA-1470-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1470-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '4.0', reference: '3.1.3-4etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
