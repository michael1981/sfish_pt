# This script was automatically generated from the dsa-524
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15361);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "524");
 script_cve_id("CVE-2004-0393", "CVE-2004-0454");
 script_bugtraq_id(10578);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-524 security update');
 script_set_attribute(attribute: 'description', value:
'jaguar@felinemenace.org discovered a format string vulnerability in
rlpr, a utility for lpd printing without using /etc/printcap.  While
investigating this vulnerability, a buffer overflow was also
discovered in related code.  By exploiting one of these
vulnerabilities, a local or remote user could potentially cause
arbitrary code to be executed with the privileges of 1) the rlprd
process (remote), or 2) root (local).
CVE-2004-0393: format string vulnerability via syslog(3) in msg()
function in rlpr
CVE-2004-0454: buffer overflow in msg() function in rlpr
For the current stable distribution (woody), this problem has been
fixed in version 2.02-7woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-524');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-524
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA524] DSA-524-1 rlpr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-524-1 rlpr");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rlpr', release: '3.0', reference: '2.02-7woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
