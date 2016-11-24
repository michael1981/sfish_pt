# This script was automatically generated from the dsa-086
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14923);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "086");
 script_cve_id("CVE-2001-0361");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-086 security update');
 script_set_attribute(attribute: 'description', value:
'We have received reports that the "SSH CRC-32 compensation attack
detector vulnerability" is being actively exploited. This is the same
integer type error previously corrected for OpenSSH in DSA-027-1.
OpenSSH (the Debian ssh package) was fixed at that time, but
ssh-nonfree and ssh-socks were not.
Though packages in the non-free section of the archive are not
officially supported by the Debian project, we are taking the unusual
step of releasing updated ssh-nonfree/ssh-socks packages for those
users who have not yet migrated to OpenSSH. However, we do recommend
that our users migrate to the regularly supported, DFSG-free "ssh"
package as soon as possible. ssh 1.2.3-9.3 is the OpenSSH package
available in Debian 2.2r4.
The fixed ssh-nonfree/ssh-socks packages are available in version
1.2.27-6.2 for use with Debian 2.2 (potato) and version 1.2.27-8 for
use with the Debian unstable/testing distribution. Note that the new
ssh-nonfree/ssh-socks packages remove the setuid bit from the ssh
binary, disabling rhosts-rsa authentication. If you need this
functionality, run
chmod u+s /usr/bin/ssh1
after installing the new package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-086');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-086
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA086] DSA-086-1 ssh-nonfree");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-086-1 ssh-nonfree");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh-askpass-nonfree', release: '2.2', reference: '1.2.27-6.2');
deb_check(prefix: 'ssh-nonfree', release: '2.2', reference: '1.2.27-6.2');
deb_check(prefix: 'ssh-socks', release: '2.2', reference: '1.2.27-6.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
