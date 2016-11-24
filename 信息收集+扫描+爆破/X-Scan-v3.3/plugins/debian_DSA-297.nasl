# This script was automatically generated from the dsa-297
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15134);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "297");
 script_cve_id("CVE-2003-0033", "CVE-2003-0209");
 script_bugtraq_id(6963, 7178);
 script_xref(name: "CERT", value: "139129");
 script_xref(name: "CERT", value: "916785");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-297 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in Snort, a popular network
intrusion detection system.  Snort comes with modules and plugins that
perform a variety of functions such as protocol analysis.  The
following issues have been identified:
For the stable distribution (woody) these problems have been fixed in
version 1.8.4beta1-3.1.
The old stable distribution (potato) is not affected by these problems
since it doesn\'t contain the problematic code.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-297');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your snort package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA297] DSA-297-1 snort");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-297-1 snort");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'snort', release: '3.0', reference: '1.8.4beta1-3.1');
deb_check(prefix: 'snort-common', release: '3.0', reference: '1.8.4beta1-3.1');
deb_check(prefix: 'snort-doc', release: '3.0', reference: '1.8.4beta1-3.1');
deb_check(prefix: 'snort-mysql', release: '3.0', reference: '1.8.4beta1-3.1');
deb_check(prefix: 'snort-rules-default', release: '3.0', reference: '1.8.4beta1-3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
