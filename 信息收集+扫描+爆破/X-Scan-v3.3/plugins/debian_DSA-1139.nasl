# This script was automatically generated from the dsa-1139
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22681);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1139");
 script_cve_id("CVE-2006-3694");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1139 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the interpreter for the Ruby language does not
properly maintain "safe levels" for aliasing, directory accesses and
regular expressions, which might lead to a bypass of security
restrictions.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.8-12sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1139');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Ruby packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1139] DSA-1139-1 ruby1.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1139-1 ruby1.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libcurses-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libdbm-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libgdbm-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libpty-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libreadline-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libruby1.6-dbg', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libsdbm-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libsyslog-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libtcltk-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'libtk-ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'ruby1.6', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'ruby1.6-dev', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'ruby1.6-elisp', release: '3.1', reference: '1.6.8-12sarge2');
deb_check(prefix: 'ruby1.6-examples', release: '3.1', reference: '1.6.8-12sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
