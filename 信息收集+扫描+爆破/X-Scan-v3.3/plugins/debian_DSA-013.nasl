# This script was automatically generated from the dsa-013
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14850);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "013");
 script_cve_id("CVE-2001-1274");
 script_bugtraq_id(2262);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-013 security update');
 script_set_attribute(attribute: 'description', value:
'Nicolas Gregoire has reported a buffer overflow in the
mysql server that leads to a remote exploit. An attacker could gain mysqld
privileges (and thus gaining access to all the databases). 

We recommend you upgrade your mysql package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-013');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-013
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA013] DSA-013 MySQL");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-013 MySQL");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mysql-client', release: '2.2', reference: '3.22.32-4');
deb_check(prefix: 'mysql-doc', release: '2.2', reference: '3.22.32-4');
deb_check(prefix: 'mysql-server', release: '2.2', reference: '3.22.32-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
