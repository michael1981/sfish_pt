# This script was automatically generated from the dsa-1478
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30125);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1478");
 script_cve_id("CVE-2008-0226", "CVE-2008-0227");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1478 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma discovered two buffer overflows in YaSSL, an SSL
implementation included in the MySQL database package, which could lead
to denial of service and possibly the execution of arbitrary code.
The old stable distribution (sarge) doesn\'t contain mysql-dfsg-5.0.
For the stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1478');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql-dfsg-5.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1478] DSA-1478-1 mysql-dfsg-5.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1478-1 mysql-dfsg-5.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient15-dev', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'libmysqlclient15off', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-client', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-client-5.0', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-common', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-server', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-server-4.1', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-server-5.0', release: '4.0', reference: '5.0.32-7etch5');
deb_check(prefix: 'mysql-dfsg-5.0', release: '4.0', reference: '5.0.32-7etch5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
