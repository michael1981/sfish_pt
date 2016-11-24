# This script was automatically generated from the dsa-977
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22843);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "977");
 script_cve_id("CVE-2006-0582", "CVE-2006-0677");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-977 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in heimdal, a free
implementation of Kerberos 5.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
CVE-2006-0582
    Privilege escalation in the rsh server allows an authenticated
    attacker to overwrite arbitrary files and gain ownership of them.
CVE-2006-0677
    A remote attacker could force the telnet server to crash before
    the user logged in, resulting in inetd turning telnetd off because
    it forked too fast.
The old stable distribution (woody) does not expose rsh and telnet servers.
For the stable distribution (sarge) these problems have been fixed in
version 0.6.3-10sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-977');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heimdal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA977] DSA-977-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-977-1 heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heimdal-clients', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-clients-x', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-dev', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-docs', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-kdc', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-servers', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal-servers-x', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libasn1-6-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libgssapi1-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libhdb7-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libkafs0-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.1', reference: '0.6.3-10sarge2');
deb_check(prefix: 'heimdal', release: '3.1', reference: '0.6.3-10sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
