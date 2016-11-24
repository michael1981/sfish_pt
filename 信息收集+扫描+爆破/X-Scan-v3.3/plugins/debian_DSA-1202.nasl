# This script was automatically generated from the dsa-1202
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22934);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1202");
 script_cve_id("CVE-2006-4573");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1202 security update');
 script_set_attribute(attribute: 'description', value:
'<q>cstone</q> and Rich Felker discovered that specially crafted UTF-8 sequences
may lead an out of bands memory write when displayed inside the screen
terminal multiplexer, allowing denial of service and potentially the
execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.2-4.1sarge1. Due to technical problems with the security
buildd infrastructure this update lacks a build for the Sun Sparc
architecture. It will be released as soon as the problems are resolved.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1202');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your screen package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1202] DSA-1202-1 screen");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1202-1 screen");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'screen', release: '3.1', reference: '4.0.2-4.1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
