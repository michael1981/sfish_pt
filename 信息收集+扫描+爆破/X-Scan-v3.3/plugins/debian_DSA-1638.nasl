# This script was automatically generated from the dsa-1638
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34223);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1638");
 script_cve_id("CVE-2006-5051", "CVE-2008-4109");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1638 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that the signal handler implementing the login
timeout in Debian\'s version of the OpenSSH server uses functions which
are not async-signal-safe, leading to a denial of service
vulnerability (CVE-2008-4109).
The problem was originally corrected in OpenSSH 4.4p1 (CVE-2006-5051),
but the patch backported to the version released with etch was
incorrect.
Systems affected by this issue suffer from lots of zombie sshd
processes.  Processes stuck with a "[net]" process title have also been
observed.  Over time, a sufficient number of processes may accumulate
such that further login attempts are impossible.  Presence of these
processes does not indicate active exploitation of this vulnerability.
It is possible to trigger this denial of service condition by accident.
For the stable distribution (etch), this problem has been fixed in
version 4.3p2-9etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1638');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssh packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1638] DSA-1638-1 openssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1638-1 openssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'openssh-client', release: '4.0', reference: '4.3p2-9etch3');
deb_check(prefix: 'openssh-server', release: '4.0', reference: '4.3p2-9etch3');
deb_check(prefix: 'ssh', release: '4.0', reference: '4.3p2-9etch3');
deb_check(prefix: 'ssh-askpass-gnome', release: '4.0', reference: '4.3p2-9etch3');
deb_check(prefix: 'ssh-krb5', release: '4.0', reference: '4.3p2-9etch3');
deb_check(prefix: 'openssh', release: '4.0', reference: '4.3p2-9etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
