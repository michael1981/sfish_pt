# This script was automatically generated from the dsa-1683
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35061);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1683");
 script_cve_id("CVE-2007-4337", "CVE-2008-4829");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1683 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple buffer overflows involving HTTP header and playlist parsing
have been discovered in streamripper (CVE-2007-4337, CVE-2008-4829).


For the stable distribution (etch), these problems have been fixed in
version 1.61.27-1+etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1683');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your streamripper package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1683] DSA-1683-1 streamripper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1683-1 streamripper");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'streamripper', release: '4.0', reference: '1.61.27-1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
