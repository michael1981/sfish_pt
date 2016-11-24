# This script was automatically generated from the dsa-1744
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35958);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1744");
 script_cve_id("CVE-2009-0661");
 script_bugtraq_id(34148);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1744 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastien Helleu discovered that an error in the handling of color codes
in the weechat IRC client could cause an out-of-bounds read of an internal
color array. This can be used by an attacker to crash user clients
via a crafted PRIVMSG command.
The weechat version in the oldstable distribution (etch) is not affected
by this problem.
For the stable distribution (lenny), this problem has been fixed in
version 0.2.6-1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1744');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your weechat packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1744] DSA-1744-1 weechat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1744-1 weechat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'weechat', release: '5.0', reference: '0.2.6-1+lenny1');
deb_check(prefix: 'weechat-common', release: '5.0', reference: '0.2.6-1+lenny1');
deb_check(prefix: 'weechat-curses', release: '5.0', reference: '0.2.6-1+lenny1');
deb_check(prefix: 'weechat-plugins', release: '5.0', reference: '0.2.6-1+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
