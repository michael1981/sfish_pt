# This script was automatically generated from the dsa-627
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16105);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "627");
 script_cve_id("CVE-2004-1318");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-627 security update');
 script_set_attribute(attribute: 'description', value:
'A cross-site scripting vulnerability has been discovered in namazu2, a
full text search engine.  An attacker could prepare specially crafted
input that would not be sanitised by namazu2 and hence displayed
verbatim for the victim.
For the stable distribution (woody) this problem has been fixed in
version 2.0.10-1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-627');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your namazu2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA627] DSA-627-1 namazu2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-627-1 namazu2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnmz3', release: '3.0', reference: '2.0.10-1woody3');
deb_check(prefix: 'libnmz3-dev', release: '3.0', reference: '2.0.10-1woody3');
deb_check(prefix: 'namazu2', release: '3.0', reference: '2.0.10-1woody3');
deb_check(prefix: 'namazu2-common', release: '3.0', reference: '2.0.10-1woody3');
deb_check(prefix: 'namazu2-index-tools', release: '3.0', reference: '2.0.10-1woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
