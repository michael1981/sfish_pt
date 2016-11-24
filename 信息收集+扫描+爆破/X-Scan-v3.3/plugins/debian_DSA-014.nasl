# This script was automatically generated from the dsa-014
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14851);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "014");
 script_cve_id("CVE-2001-0111", "CVE-2001-0112");
 script_bugtraq_id(2210);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-014 security update');
 script_set_attribute(attribute: 'description', value:
'It was reported recently that splitvt is vulnerable to
numerous buffer overflow attack and a format string attack. An attacker was
able to gain access to the root user id.

We recommend you upgrade your splitvt package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-014');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-014
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA014] DSA-014-2 splitvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-014-2 splitvt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'splitvt', release: '2.2', reference: '1.6.5-0potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
