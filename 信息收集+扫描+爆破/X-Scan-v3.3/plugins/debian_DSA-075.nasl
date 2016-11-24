# This script was automatically generated from the dsa-075
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14912);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "075");
 script_cve_id("CVE-2001-0554");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-075 security update');
 script_set_attribute(attribute: 'description', value:
'The telnet daemon contained in the netkit-telnet-ssl_0.16.3-1 package in
the \'stable\' (potato) distribution of Debian GNU/Linux is vulnerable to an
exploitable overflow in its output handling.
The original bug was found by <scut@nb.in-berlin.de>, and announced to
bugtraq on Jul 18 2001. At that time, netkit-telnet versions after 0.14 were
not believed to be vulnerable.

On Aug 10 2001, zen-parse posted an advisory based on the same problem, for
all netkit-telnet versions below 0.17.

More details can be found on
SecurityFocus.
As Debian uses the \'telnetd\' user to run in.telnetd, this is not a remote
root compromise on Debian systems; the \'telnetd\' user can be compromised.

We strongly advise you update your netkit-telnet-ssl packages to the versions
listed below.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-075');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-075
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA075] DSA-075-1 netkit-telnet-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-075-1 netkit-telnet-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssltelnet', release: '2.2', reference: '0.16.3-1.1');
deb_check(prefix: 'telnet-ssl', release: '2.2', reference: '0.16.3-1.1');
deb_check(prefix: 'telnetd-ssl', release: '2.2', reference: '0.16.3-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
