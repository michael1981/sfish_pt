# This script was automatically generated from the dsa-957
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22823);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "957");
 script_cve_id("CVE-2005-4601");
 script_bugtraq_id(16093);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-957 security update');
 script_set_attribute(attribute: 'description', value:
'Florian Weimer discovered that delegate code in ImageMagick is
vulnerable to shell command injection using specially crafted file
names.  This allows attackers to encode commands inside of graphic
commands.  With some user interaction, this is exploitable through
Gnus and Thunderbird.  This update filters out the \'$\' character as
well, which was forgotten in the former update.
For the old stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody8.
For the stable distribution (sarge) this problem has been fixed in
version 6.0.6.2-2.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-957');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA957] DSA-957-2 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-957-2 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody8');
deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody8');
deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody8');
deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody8');
deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.6');
deb_check(prefix: 'libmagick6', release: '3.1', reference: '6.0.6.2-2.6');
deb_check(prefix: 'libmagick6-dev', release: '3.1', reference: '6.0.6.2-2.6');
deb_check(prefix: 'perlmagick', release: '3.1', reference: '6.0.6.2-2.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
