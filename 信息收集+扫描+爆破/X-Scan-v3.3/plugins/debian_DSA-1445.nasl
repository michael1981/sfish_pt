# This script was automatically generated from the dsa-1445
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29839);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1445");
 script_cve_id("CVE-2008-0061");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1445 security update');
 script_set_attribute(attribute: 'description', value:
'Michael Krieger and Sam Trenholme discovered a programming error in
MaraDNS, a simple security-aware Domain Name Service server, which
might lead to denial of service through malformed DNS packets.


For the old stable distribution (sarge), this problem has been fixed
in version 1.0.27-2.


For the stable distribution (etch), this problem has been fixed in
version 1.2.12.04-1etch2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1445');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your maradns package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1445] DSA-1445-1 maradns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1445-1 maradns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'maradns', release: '3.1', reference: '1.0.27-2');
deb_check(prefix: 'maradns', release: '4.0', reference: '1.2.12.04-1etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
