# This script was automatically generated from the dsa-389
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15226);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "389");
 script_cve_id("CVE-2003-0785");
 script_bugtraq_id(8664);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-389 security update');
 script_set_attribute(attribute: 'description', value:
'ipmasq is a package which simplifies configuration of Linux IP
masquerading, a form of network address translation which allows a
number of hosts to share a single public IP address.  Due to use of
certain improper filtering rules, traffic arriving on the external
interface addressed for an internal host would be forwarded,
regardless of whether it was associated with an established
connection.  This vulnerability could be exploited by an attacker
capable of forwarding IP traffic with an arbitrary destination address
to the external interface of a system with ipmasq installed.
For the current stable distribution (woody) this problem has been
fixed in version 3.5.10c.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-389');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-389
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA389] DSA-389-1 ipmasq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-389-1 ipmasq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ipmasq', release: '3.0', reference: '3.5.10c');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
