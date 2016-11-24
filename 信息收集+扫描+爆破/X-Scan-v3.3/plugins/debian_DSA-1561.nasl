# This script was automatically generated from the dsa-1561
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32085);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1561");
 script_cve_id("CVE-2008-1293");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1561 security update');
 script_set_attribute(attribute: 'description', value:
'Christian Herzog discovered that within the Linux Terminal Server Project,
it was possible to connect to X on any LTSP client from any host on the
network, making client windows and keystrokes visible to that host.
NOTE: most ldm installs are likely to be in a chroot environment exported
over NFS, and will not be upgraded merely by upgrading the server itself.
For example, on the i386 architecture, to upgrade ldm will likely require:
    chroot /opt/ltsp/i386 apt-get update
    chroot /opt/ltsp/i386 apt-get dist-upgrade


For the stable distribution (etch), this problem has been fixed in
version 0.99debian11+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1561');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ldm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1561] DSA-1561-1 ldm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1561-1 ldm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldm', release: '4.0', reference: '0.99debian11+etch1');
deb_check(prefix: 'ltsp-client', release: '4.0', reference: '0.99debian11+etch1');
deb_check(prefix: 'ltsp-server', release: '4.0', reference: '0.99debian11+etch1');
deb_check(prefix: 'ltsp-server-standalone', release: '4.0', reference: '0.99debian11+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
