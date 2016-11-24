# This script was automatically generated from the dsa-111
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14948);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "111");
 script_cve_id("CVE-2002-0012", "CVE-2002-0013");
 script_xref(name: "CERT", value: "107186");
 script_xref(name: "CERT", value: "854306");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-111 security update');
 script_set_attribute(attribute: 'description', value:
'The Secure Programming Group of the Oulu University did a study on
SNMP implementations and uncovered multiple problems which can
cause problems ranging from Denial of Service attacks to remote
exploits.
New UCD-SNMP packages have been prepared to fix these problems
as well as a few others. The complete list of fixed problems is:
(thanks to Caldera for most of the work on those patches)
The new version is 4.1.1-2.1 and we recommend you upgrade your
snmp packages immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-111');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-111
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA111] DSA-111-1 ucd-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-111-1 ucd-snmp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsnmp4.1', release: '2.2', reference: '4.1.1-2.2');
deb_check(prefix: 'libsnmp4.1-dev', release: '2.2', reference: '4.1.1-2.2');
deb_check(prefix: 'snmp', release: '2.2', reference: '4.1.1-2.2');
deb_check(prefix: 'snmpd', release: '2.2', reference: '4.1.1-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
