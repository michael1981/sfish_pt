# This script was automatically generated from the dsa-171
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15008);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "171");
 script_cve_id("CVE-2002-1174", "CVE-2002-1175");
 script_bugtraq_id(5825, 5826, 5827);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-171 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser discovered several buffer overflows and a broken boundary
check within fetchmail.  If fetchmail is running in multidrop mode
these flaws can be used by remote attackers to crash it or to execute
arbitrary code under the user id of the user running fetchmail.
Depending on the configuration this even allows a remote root
compromise.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-171');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA171] DSA-171-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-171-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-4.2');
deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-4.2');
deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.1');
deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.1');
deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.1');
deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
