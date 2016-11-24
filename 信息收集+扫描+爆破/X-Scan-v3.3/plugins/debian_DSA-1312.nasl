# This script was automatically generated from the dsa-1312
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25556);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1312");
 script_cve_id("CVE-2007-1860");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1312 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the Apache 1.3 connector for the Tomcat Java
servlet engine decoded request URLs multiple times, which can lead
to information disclosure.
For the oldstable distribution (sarge) this problem has been fixed in
version 1.2.5-2sarge1. An updated package for powerpc is not yet
available due to problems with the build host. It will be provided
later.
For the stable distribution (etch) this problem has been fixed in
version 1.2.18-3etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1312');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-jk package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1312] DSA-1312-1 libapache-mod-jk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1312-1 libapache-mod-jk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-jk', release: '3.1', reference: '1.2.5-2sarge1');
deb_check(prefix: 'libapache-mod-jk', release: '4.0', reference: '1.2.18-3etch1');
deb_check(prefix: 'libapache-mod-jk-doc', release: '4.0', reference: '1.2.18-3etch1');
deb_check(prefix: 'libapache2-mod-jk', release: '4.0', reference: '1.2.18-3etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
