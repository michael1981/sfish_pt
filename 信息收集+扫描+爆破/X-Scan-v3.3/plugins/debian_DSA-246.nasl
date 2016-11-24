# This script was automatically generated from the dsa-246
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15083);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "246");
 script_cve_id("CVE-2003-0042", "CVE-2003-0043", "CVE-2003-0044");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-246 security update');
 script_set_attribute(attribute: 'description', value:
'The developers of tomcat discovered several problems in tomcat version
3.x.  The Common Vulnerabilities and Exposures project identifies the
following problems:
For the stable distribution (woody) this problem has been fixed in
version 3.3a-4woody.1.
The old stable distribution (potato) does not contain tomcat packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-246');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tomcat package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA246] DSA-246-1 tomcat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-246-1 tomcat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-jk', release: '3.0', reference: '3.3a-4woody1');
deb_check(prefix: 'tomcat', release: '3.0', reference: '3.3a-4woody1');
deb_check(prefix: 'tomcat', release: '3.0', reference: '3.3a-4woody.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
