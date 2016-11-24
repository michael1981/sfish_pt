# This script was automatically generated from the dsa-327
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15164);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "327");
 script_cve_id("CVE-2003-0451");
 script_bugtraq_id(7989);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-327 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered several buffer overflows in xbl, a game, which
can be triggered by long command line arguments.  This vulnerability
could be exploited by a local attacker to gain gid \'games\'.
For the stable distribution (woody) this problem has been fixed in
version 1.0k-3woody1.
For the old stable distribution (potato) this problem has been fixed
in version 1.0i-7potato1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-327');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-327
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA327] DSA-327-1 xbl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-327-1 xbl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xbl', release: '2.2', reference: '1.0i-7potato1');
deb_check(prefix: 'xbl', release: '3.0', reference: '1.0k-3woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
