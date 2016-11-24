# This script was automatically generated from the dsa-254
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15091);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "254");
 script_cve_id("CVE-2002-1051", "CVE-2002-1364", "CVE-2002-1386", "CVE-2002-1387");
 script_bugtraq_id(4956, 6166, 6274, 6275);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-254 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in NANOG traceroute, an enhanced
version of the Van Jacobson/BSD traceroute program.  A buffer overflow
occurs in the \'get_origin()\' function.  Due to insufficient bounds
checking performed by the whois parser, it may be possible to corrupt
memory on the system stack.  This vulnerability can be exploited by a
remote attacker to gain root privileges on a target host.  Though,
most probably not in Debian.
The Common Vulnerabilities and Exposures (CVE) project additionally
identified the following vulnerabilities which were already fixed in
the Debian version in stable (woody) and oldstable (potato) and are
mentioned here for completeness (and since other distributions had to
release a separate advisory for them):
Fortunately, the Debian package drops privileges quite early after
startup, so those problems are not likely to result in an exploit on a
Debian machine.
For the current stable distribution (woody) the above problem has been
fixed in version 6.1.1-1.2.
For the old stable distribution (potato) the above problem has been
fixed in version 6.0-2.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-254');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your traceroute-nanog package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA254] DSA-254-1 traceroute-nanog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-254-1 traceroute-nanog");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'traceroute-nanog', release: '2.2', reference: '6.0-2.2');
deb_check(prefix: 'traceroute-nanog', release: '3.0', reference: '6.1.1-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
