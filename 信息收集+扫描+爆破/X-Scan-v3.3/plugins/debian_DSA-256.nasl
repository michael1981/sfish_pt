# This script was automatically generated from the dsa-256
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15093);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "256");
 script_cve_id("CVE-2003-0120");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-256 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in adb2mhc from the mhc-utils package.  The
default temporary directory uses a predictable name.  This adds a
vulnerability that allows a local attacker to overwrite arbitrary
files the users has write permissions for.
For the stable distribution (woody) this problem has been
fixed in version 0.25+20010625-7.1.
The old stable distribution (potato) does not contain mhc
packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-256');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mhc-utils packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA256] DSA-256-1 mhc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-256-1 mhc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mhc', release: '3.0', reference: '0.25+20010625-7.1');
deb_check(prefix: 'mhc-utils', release: '3.0', reference: '0.25+20010625-7.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
