# This script was automatically generated from the dsa-952
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22818);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "952");
 script_cve_id("CVE-2006-0150");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-952 security update');
 script_set_attribute(attribute: 'description', value:
'"Seregorn" discovered a format string vulnerability in the logging
function of libapache-auth-ldap, an LDAP authentication module for the
Apache webserver, that can lead to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.0-3.1.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.0-8.1
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-952');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-auth-ldap package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA952] DSA-952-1 libapache-auth-ldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-952-1 libapache-auth-ldap");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-auth-ldap', release: '3.0', reference: '1.6.0-3.1');
deb_check(prefix: 'libapache-auth-ldap', release: '3.1', reference: '1.6.0-8.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
