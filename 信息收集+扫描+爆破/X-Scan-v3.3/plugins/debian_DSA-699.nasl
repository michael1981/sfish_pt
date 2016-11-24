# This script was automatically generated from the dsa-699
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17641);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "699");
 script_cve_id("CVE-2005-0469");
 script_xref(name: "CERT", value: "291924");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-699 security update');
 script_set_attribute(attribute: 'description', value:
'Gaël Delalleau discovered a buffer overflow in the handling of
the LINEMODE suboptions in telnet clients.  This can lead to the
execution of arbitrary code when connected to a malicious server.
For the stable distribution (woody) this problem has been fixed in
version 0.17.17+0.1-2woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-699');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your telnet-ssl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA699] DSA-699-1 netkit-telnet-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-699-1 netkit-telnet-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'telnet-ssl', release: '3.0', reference: '0.17.17+0.1-2woody4');
deb_check(prefix: 'telnetd-ssl', release: '3.0', reference: '0.17.17+0.1-2woody4');
deb_check(prefix: 'netkit-telnet-ssl', release: '3.0', reference: '0.17.17+0.1-2woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
