# This script was automatically generated from the dsa-1165
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22707);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1165");
 script_cve_id("CVE-2006-3126");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1165 security update');
 script_set_attribute(attribute: 'description', value:
'Lionel Elie Mamane discovered a security vulnerability in
capi4hylafax, tools for faxing over a CAPI 2.0 device, that allows
remote attackers to execute arbitrary commands on the fax receiving
system.
For the stable distribution (sarge) this problem has been fixed in
version 01.02.03-10sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1165');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your capi4hylafax package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1165] DSA-1165-1 capi4hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1165-1 capi4hylafax");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'capi4hylafax', release: '3.1', reference: '01.02.03-10sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
