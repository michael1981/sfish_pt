# This script was automatically generated from the dsa-512
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15349);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "512");
 script_cve_id("CVE-2004-0522");
 script_bugtraq_id(10451);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-512 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in gallery, a web-based photo album
written in php, whereby a remote attacker could gain access to the
gallery "admin" user without proper authentication.  No CVE candidate
was available for this vulnerability at the time of release.
For the current stable distribution (woody), these problems have been
fixed in version 1.2.5-8woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-512');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-512
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA512] DSA-512-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-512-1 gallery");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
