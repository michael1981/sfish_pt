# This script was automatically generated from the dsa-245
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15082);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "245");
 script_cve_id("CVE-2003-0039");
 script_bugtraq_id(6628);
 script_xref(name: "CERT", value: "149953");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-245 security update');
 script_set_attribute(attribute: 'description', value:
'Florian Lohoff discovered a bug in the dhcrelay causing it to send a
continuing packet storm towards the configured DHCP server(s) in case
of a malicious BOOTP packet, such as sent from buggy Cisco switches.
When the dhcp-relay receives a BOOTP request it forwards the request
to the DHCP server using the broadcast MAC address ff:ff:ff:ff:ff:ff
which causes the network interface to reflect the packet back into the
socket.  To prevent loops the dhcrelay checks whether the
relay-address is its own, in which case the packet would be dropped.
In combination with a missing upper boundary for the hop counter an
attacker can force the dhcp-relay to send a continuing packet storm
towards the configured dhcp server(s).
This patch introduces a new command line switch -c maxcount and
people are advised to start the dhcp-relay with dhcrelay -c 10
or a smaller number, which will only create that many packets.
The dhcrelay program from the "dhcp" package does not seem to be
affected since DHCP packets are dropped if they were apparently
relayed already.
For the stable distribution (woody) this problem has been fixed in
version 3.0+3.0.1rc9-2.2.
The old stable distribution (potato) does not contain dhcp3 packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-245');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dhcp3 package when you are using
the dhcrelay server.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA245] DSA-245-1 dhcp3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-245-1 dhcp3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dhcp3-client', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
deb_check(prefix: 'dhcp3-common', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
deb_check(prefix: 'dhcp3-dev', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
deb_check(prefix: 'dhcp3-relay', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
deb_check(prefix: 'dhcp3-server', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
deb_check(prefix: 'dhcp3', release: '3.0', reference: '3.0+3.0.1rc9-2.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
