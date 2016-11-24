# This script was automatically generated from the dsa-1605
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33452);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1605");
 script_cve_id("CVE-2008-1447");
 script_xref(name: "CERT", value: "800113");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1605 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS spoofing and cache poisoning attacks.  Among
other things, successful attacks can lead to misdirected web traffic
and email rerouting.
At this time, it is not possible to implement the recommended
countermeasures in the GNU libc stub resolver.  The following
workarounds are available:
1. Install a local BIND 9 resolver on the host, possibly in
forward-only mode.  BIND 9 will then use source port randomization
when sending queries over the network.  (Other caching resolvers can
be used instead.)
2. Rely on IP address spoofing protection if available.  Successful
attacks must spoof the address of one of the resolvers, which may not
be possible if the network is guarded properly against IP spoofing
attacks (both from internal and external sources).
This DSA will be updated when patches for hardening the stub resolver
are available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1605');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2008/dsa-1605
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1605] DSA-1605-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1605-1 glibc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
