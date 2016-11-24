# This script was automatically generated from the dsa-1410
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28299);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1410");
 script_cve_id("CVE-2007-5162", "CVE-2007-5770");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1410 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Ruby, an object-oriented
scripting language. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2007-5162
    It was discovered that the Ruby HTTP(S) module performs insufficient
    validation of SSL certificates, which may lead to man-in-the-middle
    attacks.
CVE-2007-5770
    It was discovered that the Ruby modules for FTP, Telnet, IMAP, POP
    and SMTP perform insufficient validation of SSL certificates, which
    may lead to man-in-the-middle attacks.
For the old stable distribution (sarge) these problems have been fixed
in version 1.8.2-7sarge6. Packages for sparc will be provided later.
For the stable distribution (etch) these problems have been fixed in
version 1.8.5-4etch1. Packages for sparc will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1410');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1410] DSA-1410-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1410-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libgdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libopenssl-ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libreadline-ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libruby1.8-dbg', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'libtcltk-ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'rdoc1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'ri1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'ruby1.8', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'ruby1.8-dev', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'ruby1.8-elisp', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'ruby1.8-examples', release: '3.1', reference: '1.8.2-7sarge6');
deb_check(prefix: 'irb1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libgdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libopenssl-ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libreadline-ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libruby1.8-dbg', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'libtcltk-ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'rdoc1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'ri1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'ruby1.8', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'ruby1.8-dev', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'ruby1.8-elisp', release: '4.0', reference: '1.8.5-4etch1');
deb_check(prefix: 'ruby1.8-examples', release: '4.0', reference: '1.8.5-4etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
