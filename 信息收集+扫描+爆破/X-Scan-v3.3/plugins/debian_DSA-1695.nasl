# This script was automatically generated from the dsa-1695
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35294);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1695");
 script_cve_id("CVE-2008-3443");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1695 security update');
 script_set_attribute(attribute: 'description', value:
'The regular expression engine of Ruby, a scripting language, contains a
memory leak which can be triggered remotely under certain circumstances,
leading to a denial of service condition (CVE-2008-3443).
In addition, this security update addresses a regression in the REXML
XML parser of the ruby1.8 package; the regression was introduced in
DSA-1651-1.
For the stable distribution (etch), this problem has been fixed in version
1.8.5-4etch4 of the ruby1.8 package, and version 1.9.0+20060609-1etch4
of the ruby1.9 package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1695');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Ruby packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1695] DSA-1695-1 ruby1.8, ruby1.9");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1695-1 ruby1.8, ruby1.9");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'irb1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libdbm-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libgdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libgdbm-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libopenssl-ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libopenssl-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libreadline-ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libreadline-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libruby1.8-dbg', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libruby1.9-dbg', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'libtcltk-ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'libtcltk-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'rdoc1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'rdoc1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'ri1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'ri1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'ruby1.8', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'ruby1.8-dev', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'ruby1.8-elisp', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'ruby1.8-examples', release: '4.0', reference: '1.8.5-4etch4');
deb_check(prefix: 'ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'ruby1.9-dev', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'ruby1.9-elisp', release: '4.0', reference: '1.9.0+20060609-1etch4');
deb_check(prefix: 'ruby1.9-examples', release: '4.0', reference: '1.9.0+20060609-1etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
