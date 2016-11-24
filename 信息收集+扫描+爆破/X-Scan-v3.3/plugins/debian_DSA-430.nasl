# This script was automatically generated from the dsa-430
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15267);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "430");
 script_cve_id("CVE-2004-0047");
 script_bugtraq_id(9520);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-430 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered a problem in trr19, a type trainer application
for GNU Emacs, which is written as a pair of setgid() binaries and
wrapper programs which execute commands for GNU Emacs.  However, the
binaries don\'t drop privileges before executing a command, allowing an
attacker to gain access to the local group games.
For the stable distribution (woody) this problem has been fixed in
version 1.0beta5-15woody1.  The mipsel binary will be added later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-430');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your trr19 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA430] DSA-430-1 trr19");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-430-1 trr19");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'trr19', release: '3.0', reference: '1.0beta5-15woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
