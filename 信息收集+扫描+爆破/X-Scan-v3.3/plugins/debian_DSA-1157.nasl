# This script was automatically generated from the dsa-1157
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22699);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1157");
 script_cve_id("CVE-2006-1931", "CVE-2006-3694");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1157 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the interpreter for the
Ruby language, which may lead to the bypass of security restrictions or
denial of service. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2006-1931
    It was discovered that the use of blocking sockets can lead to denial
    of service.
CVE-2006-3964
    It was discovered that Ruby does not properly maintain "safe levels"
    for aliasing, directory accesses and regular expressions, which might
    lead to a bypass of security restrictions.
For the stable distribution (sarge) these problems have been fixed in
version 1.8.2-7sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1157');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Ruby packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1157] DSA-1157-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1157-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libgdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libopenssl-ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libreadline-ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libruby1.8-dbg', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'libtcltk-ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'rdoc1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'ri1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'ruby1.8', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'ruby1.8-dev', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'ruby1.8-elisp', release: '3.1', reference: '1.8.2-7sarge4');
deb_check(prefix: 'ruby1.8-examples', release: '3.1', reference: '1.8.2-7sarge4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
