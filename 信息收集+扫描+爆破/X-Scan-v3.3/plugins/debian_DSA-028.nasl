# This script was automatically generated from the dsa-028
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14865);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "028");
 script_cve_id("CVE-2001-0193");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-028 security update');
 script_set_attribute(attribute: 'description', value:
'Styx has reported that the program `man\' mistakenly passes
malicious strings (i.e. containing format characters) through routines that
were not meant to use them as format strings. Since this could cause a
segmentation fault and privileges were not dropped it may lead to an exploit
for the \'man\' user. 

We recommend you upgrade your man-db package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-028');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-028
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA028] DSA-028-1 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-028-1 man-db");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'man-db', release: '2.2', reference: '2.3.16-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
