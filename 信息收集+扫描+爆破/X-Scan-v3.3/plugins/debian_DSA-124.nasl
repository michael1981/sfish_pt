# This script was automatically generated from the dsa-124
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14961);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "124");
 script_cve_id("CVE-2002-0497");
 script_bugtraq_id(4217);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-124 security update');
 script_set_attribute(attribute: 'description', value:
'The authors of mtr released a new upstream version, noting a
non-exploitable buffer overflow in their ChangeLog.  Przemyslaw
Frasunek, however, found an easy way to exploit this bug, which allows
an attacker to gain access to the raw socket, which makes IP spoofing
and other malicious network activity possible.
The problem has been fixed by the Debian maintainer in version 0.41-6
for the stable distribution of Debian by backporting the upstream fix
and in version 0.48-1 for the testing/unstable distribution.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-124');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mtr package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA124] DSA-124-1 mtr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-124-1 mtr");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mtr', release: '2.2', reference: '0.41-6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
