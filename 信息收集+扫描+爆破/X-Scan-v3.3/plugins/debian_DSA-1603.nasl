# This script was automatically generated from the dsa-1603
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);
if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description) {
 script_id(33450);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "1603");
 script_cve_id("CVE-2008-1447");
 script_xref(name: "CERT", value: "800113");

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-1603 security update.");
 script_set_attribute(attribute: "description", value: 
'Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks.  Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.
This update changes Debian\'s BIND 9 packages to implement the
recommended countermeasure: UDP query source port randomization.  This
change increases the size of the space from which an attacker has to
guess values in a backwards-compatible fashion and makes successful
attacks significantly more difficult.
Note that this security update changes BIND network behavior in a
fundamental way, and the following steps are recommended to ensure a
smooth upgrade.
1. Make sure that your network configuration is compatible with source
port randomization.  If you guard your resolver with a stateless packet
filter, you may need to make sure that no non-DNS services listen on
the 1024--65535 UDP port range and open it at the packet filter.  For
instance, packet filters based on etch\'s Linux 2.6.18 kernel only
support stateless filtering of IPv6 packets, and therefore pose this
additional difficulty.  (If you use IPv4 with iptables and ESTABLISHED
rules, networking changes are likely not required.)
2. Install the BIND 9 upgrade, using "apt-get update" followed by
"apt-get install bind9".  Verify that the named process has been
restarted and answers recursive queries.  (If all queries result in
timeouts, this indicates that networking changes are necessary; see the
first step.)
3. Verify that source port randomization is active.  Check that the
/var/log/daemon.log file does not contain messages of the following
form
  named[6106]: /etc/bind/named.conf.options:28: using specific query-source port suppresses port randomization and can be insecure.

right after the "listening on IPv6 interface" and "listening on IPv4
interface" messages logged by BIND upon startup.  If these messages are
present, you should remove the indicated lines from the configuration,
or replace the port numbers contained within them with "*" sign (e.g.,
replace "port 53" with "port *").
For additional certainty, use tcpdump or some other network monitoring
tool to check for varying UDP source ports.  If there is a NAT device
in front of your resolver, make sure that it does not defeat the
effect of source port randomization.
4. If you cannot activate source port randomization, consider
configuring BIND 9 to forward queries to a resolver which can, possibly
over a VPN such as OpenVPN to create the necessary trusted network link.
(Use BIND\'s forward-only mode in this case.)
Other caching resolvers distributed by Debian (PowerDNS, MaraDNS,
Unbound) already employ source port randomization, and no updated
packages are needed.  BIND 9.5 up to and including version
1:9.5.0.dfsg-4 only implements a weak form of source port
randomization and needs to be updated as well.  For information on
BIND 8, see DSA-1604-1, and for the status of
the libc stub resolver, see DSA-1605-1.
The updated bind9 packages contain changes originally scheduled for
the next stable point release, including the changed IP address of
L.ROOT-SERVERS.NET (Debian bug #449148).
For the stable 
[...]');
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2008/dsa-1603");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2008/dsa-1603
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1603] DSA-1603-1 bind9");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1603-1 bind9");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'bind9', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'bind9-doc', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'bind9-host', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'dnsutils', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libbind-dev', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libbind9-0', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libdns22', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libisc11', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libisccc0', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'libisccfg1', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'liblwres9', release: '4.0', reference: '9.3.4-2etch3');
deb_check(prefix: 'lwresd', release: '4.0', reference: '9.3.4-2etch3');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
