# This script was automatically generated from the dsa-1132
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22674);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1132");
 script_cve_id("CVE-2006-3747");
 script_xref(name: "CERT", value: "395412");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1132 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Dowd discovered a buffer overflow in the mod_rewrite component of
apache, a versatile high-performance HTTP server.  In some situations a
remote attacker could exploit this to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.54-5sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1132');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apache2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1132] DSA-1132-1 apache2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1132-1 apache2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-common', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-doc', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-mpm-perchild', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-mpm-prefork', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-mpm-threadpool', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-mpm-worker', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-prefork-dev', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-threaded-dev', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'apache2-utils', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'libapr0', release: '3.1', reference: '2.0.54-5sarge1');
deb_check(prefix: 'libapr0-dev', release: '3.1', reference: '2.0.54-5sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
