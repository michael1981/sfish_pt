# This script was automatically generated from the dsa-935
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22801);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "935");
 script_cve_id("CVE-2005-3656");
 script_bugtraq_id(16153);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-935 security update');
 script_set_attribute(attribute: 'description', value:
'iDEFENSE reports that a format string vulnerability in mod_auth_pgsql, a
library used to authenticate web users against a PostgreSQL database,
could be used to execute arbitrary code with the privileges of the httpd
user.
The old stable distribution (woody) does not contain
libapache2-mod-auth-pgsql.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.2b1-5sarge0.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-935');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache2-mod-auth-pgsql package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA935] DSA-935-1 libapache2-mod-auth-pgsql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-935-1 libapache2-mod-auth-pgsql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache2-mod-auth-pgsql', release: '3.1', reference: '2.0.2b1-5sarge0');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
