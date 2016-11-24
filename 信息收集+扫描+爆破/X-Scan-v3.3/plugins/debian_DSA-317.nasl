# This script was automatically generated from the dsa-317
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15154);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "317");
 script_cve_id("CVE-2003-0195");
 script_bugtraq_id(7637);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-317 security update');
 script_set_attribute(attribute: 'description', value:
'The CUPS print server in Debian is vulnerable to a denial of service
when an HTTP request is received without being properly terminated.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5.
For the old stable distribution (potato) this problem has been fixed
in version 1.0.4-12.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-317');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-317
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA317] DSA-317-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-317-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.2');
deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-12.2');
deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-12.2');
deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-12.2');
deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
