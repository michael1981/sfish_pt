# This script was automatically generated from the dsa-1462
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29939);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1462");
 script_cve_id("CVE-2007-5208");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1462 security update');
 script_set_attribute(attribute: 'description', value:
'Kees Cook discovered that the hpssd tool of the HP Linux Printing and
Imaging System (HPLIP) performs insufficient input sanitising of shell
meta characters, which may result in local privilege escalation to
the hplip user.


The old stable distribution (sarge) is not affected by this problem.


For the stable distribution (etch), this problem has been fixed in
version 1.6.10-3etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1462');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hplip packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1462] DSA-1462-1 hplip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1462-1 hplip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hpijs', release: '4.0', reference: '2.6.10+1.6.10-3etch1');
deb_check(prefix: 'hpijs-ppds', release: '4.0', reference: '2.6.10+1.6.10-3etch1');
deb_check(prefix: 'hplip', release: '4.0', reference: '1.6.10-3etch1');
deb_check(prefix: 'hplip-data', release: '4.0', reference: '1.6.10-3etch1');
deb_check(prefix: 'hplip-dbg', release: '4.0', reference: '1.6.10-3etch1');
deb_check(prefix: 'hplip-doc', release: '4.0', reference: '1.6.10-3etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
