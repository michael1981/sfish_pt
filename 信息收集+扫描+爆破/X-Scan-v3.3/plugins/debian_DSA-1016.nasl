# This script was automatically generated from the dsa-1016
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22558);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1016");
 script_cve_id("CVE-2005-2549", "CVE-2005-2550");
 script_bugtraq_id(14532);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1016 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered several format string vulnerabilities in
Evolution, a free groupware suite, that could lead to crashes of the
application or the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed
in version 1.0.5-1woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.4-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1016');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your evolution package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1016] DSA-1016-1 evolution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1016-1 evolution");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'evolution', release: '3.0', reference: '1.0.5-1woody3');
deb_check(prefix: 'libcamel-dev', release: '3.0', reference: '1.0.5-1woody3');
deb_check(prefix: 'libcamel0', release: '3.0', reference: '1.0.5-1woody3');
deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.4-2sarge1');
deb_check(prefix: 'evolution-dev', release: '3.1', reference: '2.0.4-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
