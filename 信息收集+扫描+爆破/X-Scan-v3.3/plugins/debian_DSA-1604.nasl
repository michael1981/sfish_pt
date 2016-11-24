# This script was automatically generated from the dsa-1604
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33451);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1604");
 script_cve_id("CVE-2008-1447");
 script_xref(name: "CERT", value: "800113");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1604 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks.  Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.
The BIND 8 legacy code base could not be updated to include the
recommended countermeasure (source port randomization, see
DSA-1603-1
for details).  There are two ways to deal with this situation:
1. Upgrade to BIND 9 (or another implementation with source port
randomization).  The documentation included with BIND 9 contains a
migration guide.
2. Configure the BIND 8 resolver to forward queries to a BIND 9
resolver.  Provided that the network between both resolvers is trusted,
this protects the BIND 8 resolver from cache poisoning attacks (to the
same degree that the BIND 9 resolver is protected).
This problem does not apply to BIND 8 when used exclusively as an
authoritative DNS server.  It is theoretically possible to safely use
BIND 8 in this way, but updating to BIND 9 is strongly recommended.
BIND 8 (that is, the bind package) will be removed from the etch
distribution in a future point release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1604');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2008/dsa-1604
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1604] DSA-1604-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1604-1 bind");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
