# This script was automatically generated from the dsa-349
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15186);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "349");
 script_cve_id("CVE-2003-0252");
 script_bugtraq_id(8179);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-349 security update');
 script_set_attribute(attribute: 'description', value:
'The logging code in nfs-utils contains an off-by-one buffer overrun
when adding a newline to the string being logged.  This vulnerability
may allow an attacker to execute arbitrary code or cause a denial of
service condition by sending certain RPC requests.
For the stable distribution (woody) this problem has been fixed in
version 1:1.0-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-349');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-349
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA349] DSA-349-1 nfs-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-349-1 nfs-utils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nfs-common', release: '3.0', reference: '1.0-2woody1');
deb_check(prefix: 'nfs-kernel-server', release: '3.0', reference: '1.0-2woody1');
deb_check(prefix: 'nhfsstone', release: '3.0', reference: '1.0-2woody1');
deb_check(prefix: 'nfs-utils', release: '3.0', reference: '1.0-2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
