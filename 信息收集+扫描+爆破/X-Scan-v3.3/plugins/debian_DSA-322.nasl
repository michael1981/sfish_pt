# This script was automatically generated from the dsa-322
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15159);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "322");
 script_cve_id("CVE-2003-0435");
 script_bugtraq_id(7891);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-322 security update');
 script_set_attribute(attribute: 'description', value:
'typespeed is a game which challenges the player to type words
correctly and quickly.  It contains a network play mode which allows
players on different systems to play competitively.  The network code
contains a buffer overflow which could allow a remote attacker to
execute arbitrary code under the privileges of the user invoking
typespeed, in addition to gid games.
For the stable distribution (woody) this problem has been fixed in
version 0.4.1-2.2.
For the old stable distribution (potato) this problem has been fixed
in version 0.4.0-5.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-322');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-322
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA322] DSA-322-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-322-1 typespeed");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'typespeed', release: '2.2', reference: '0.4.0-5.2');
deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
