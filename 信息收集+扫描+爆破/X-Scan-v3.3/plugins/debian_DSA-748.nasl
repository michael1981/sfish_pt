# This script was automatically generated from the dsa-748
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18663);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "748");
 script_cve_id("CVE-2005-1992");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-748 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in ruby1.8 that could allow arbitrary
command execution on a server running the ruby xmlrpc server. 
The old stable distribution (woody) did not include ruby1.8.
This problem is fixed for the current stable distribution (sarge) in
version 1.8.2-7sarge1.
This problem is fixed for the unstable distribution in version 1.8.2-8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-748');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA748] DSA-748-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-748-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libgdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libopenssl-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libreadline-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libruby1.8-dbg', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'libtcltk-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'rdoc1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'ri1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'ruby1.8', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'ruby1.8-dev', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'ruby1.8-elisp', release: '3.1', reference: '1.8.2-7sarge1');
deb_check(prefix: 'ruby1.8-examples', release: '3.1', reference: '1.8.2-7sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
