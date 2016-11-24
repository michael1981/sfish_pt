# This script was automatically generated from the dsa-849
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19957);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "849");
 script_cve_id("CVE-2005-2317");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-849 security update');
 script_set_attribute(attribute: 'description', value:
'"Supernaut" noticed that shorewall, the Shoreline Firewall, could
generate an iptables configuration which is significantly more
permissive than the rule set given in the shorewall configuration, if
MAC verification are used in a non-default manner.
When MACLIST_DISPOSITION is set to ACCEPT in the shorewall.conf file,
all packets from hosts which fail the MAC verification pass through
the firewall, without further checks.  When MACLIST_TTL is set to a
non-zero value, packets from hosts which pass the MAC verification
pass through the firewall, again without further checks.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.3-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-849');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your shorewall package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA849] DSA-849-1 shorewall");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-849-1 shorewall");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'shorewall', release: '3.1', reference: '2.2.3-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
