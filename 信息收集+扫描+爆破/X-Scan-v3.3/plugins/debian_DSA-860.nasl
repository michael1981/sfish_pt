# This script was automatically generated from the dsa-860
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19968);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "860");
 script_cve_id("CVE-2005-2337");
 script_xref(name: "CERT", value: "160012");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-860 security update');
 script_set_attribute(attribute: 'description', value:
'Yutaka Oiwa discovered a bug in Ruby, the interpreter for the
object-oriented scripting language, that can cause illegal program
code to bypass the safe level and taint flag protections check and be
executed.  The following matrix lists the fixed versions in our
distributions:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-860');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA860] DSA-860-1 ruby");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-860-1 ruby");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libcurses-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libdbm-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libgdbm-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libnkf-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libpty-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libreadline-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libsdbm-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libsyslog-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libtcltk-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'libtk-ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'ruby', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'ruby-dev', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'ruby-elisp', release: '3.0', reference: '1.6.7-3woody5');
deb_check(prefix: 'ruby-examples', release: '3.0', reference: '1.6.7-3woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
