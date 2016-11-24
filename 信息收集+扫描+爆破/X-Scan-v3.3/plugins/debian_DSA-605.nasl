# This script was automatically generated from the dsa-605
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15907);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "605");
 script_cve_id("CVE-2004-0915");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-605 security update');
 script_set_attribute(attribute: 'description', value:
'Haris Sehic discovered several vulnerabilities in viewcvs, a utility
for viewing CVS and Subversion repositories via HTTP.  When exporting
a repository as a tar archive the hide_cvsroot and forbidden settings
were not honoured enough.
When upgrading the package for woody, please make a copy of your
/etc/viewcvs/viewcvs.conf file if you have manually edited this file.
Upon upgrade the debconf mechanism may alter it in a way so that
viewcvs doesn\'t understand it anymore.
For the stable distribution (woody) these problems have been fixed in
version 0.9.2-4woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-605');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your viewcvs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA605] DSA-605-1 viewcvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-605-1 viewcvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'viewcvs', release: '3.0', reference: '0.9.2-4woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
