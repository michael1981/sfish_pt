# This script was automatically generated from the dsa-907
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22773);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "907");
 script_cve_id("CVE-2004-2569");
 script_bugtraq_id(10269);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-907 security update');
 script_set_attribute(attribute: 'description', value:
'Akira Yoshiyama noticed that ipmenu, an cursel iptables/iproute2 GUI,
creates a temporary file in an insecure fashion allowing a local
attacker to overwrite arbitrary files utilising a symlink attack.
For the old stable distribution (woody) this problem has been fixed in
version 0.0.3-4woody1
The stable distribution (sarge) does not contain the ipmenu package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-907');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ipmenu package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA907] DSA-907-1 ipmenu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-907-1 ipmenu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ipmenu', release: '3.0', reference: '0.0.3-4woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
