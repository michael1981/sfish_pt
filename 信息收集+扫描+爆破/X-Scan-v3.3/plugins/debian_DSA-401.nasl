# This script was automatically generated from the dsa-401
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15238);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "401");
 script_cve_id("CVE-2003-0886");
 script_bugtraq_id(9005);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-401 security update');
 script_set_attribute(attribute: 'description', value:
'The SuSE Security Team discovered several exploitable formats string
vulnerabilities in hylafax, a flexible client/server fax system, which
could lead to executing arbitrary code as root on the fax server.
For the stable distribution (woody) this problem has been fixed in
version 4.1.1-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-401');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hylafax packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA401] DSA-401-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-401-1 hylafax");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-3');
deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-3');
deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-3');
deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-1.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
