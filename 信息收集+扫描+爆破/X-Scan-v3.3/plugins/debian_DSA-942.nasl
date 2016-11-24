# This script was automatically generated from the dsa-942
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22808);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "942");
 script_cve_id("CVE-2006-0044");
 script_bugtraq_id(16252);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-942 security update');
 script_set_attribute(attribute: 'description', value:
'A design error has been discovered in the Albatross web application
toolkit that causes user supplied data to be used as part of template
execution and hence arbitrary code execution.
The old stable distribution (woody) does not contain albatross packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.20-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-942');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your albatross package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA942] DSA-942-1 albatross");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-942-1 albatross");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-albatross', release: '3.1', reference: '1.20-2');
deb_check(prefix: 'python-albatross-common', release: '3.1', reference: '1.20-2');
deb_check(prefix: 'python-albatross-doc', release: '3.1', reference: '1.20-2');
deb_check(prefix: 'python2.2-albatross', release: '3.1', reference: '1.20-2');
deb_check(prefix: 'python2.3-albatross', release: '3.1', reference: '1.20-2');
deb_check(prefix: 'albatross', release: '3.1', reference: '1.20-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
