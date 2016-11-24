# This script was automatically generated from the dsa-255
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15092);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "255");
 script_cve_id("CVE-2002-0380", "CVE-2003-0108");
 script_bugtraq_id(4890, 6974);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-255 security update');
 script_set_attribute(attribute: 'description', value:
'Andrew Griffiths and iDEFENSE Labs discovered a problem in tcpdump, a
powerful tool for network monitoring and data acquisition.  An
attacker is able to send a specially crafted network packet which
causes tcpdump to enter an infinite loop.
In addition to the above problem the tcpdump developers discovered a
potential infinite loop when parsing malformed BGP packets.  They also
discovered a buffer overflow that can be exploited with certain
malformed NFS packets.
For the stable distribution (woody) these problems have been
fixed in version 3.6.2-2.3.
The old stable distribution (potato) does not seem to be affected
by these problems.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-255');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tcpdump packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA255] DSA-255-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-255-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
