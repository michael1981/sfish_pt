# This script was automatically generated from the dsa-1655
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34444);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1655");
 script_cve_id("CVE-2008-1514", "CVE-2008-3525", "CVE-2008-3831", "CVE-2008-4113", "CVE-2008-4445");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1655 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, privilege escalation or a leak of
sensitive data. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-1514
    Jan Kratochvil reported a local denial of service vulnerability in
    the ptrace interface for the s390 architecture. Local users can
    trigger an invalid pointer dereference, leading to a system panic.
CVE-2008-3525
    Eugene Teo reported a lack of capability checks in the kernel
    driver for Granch SBNI12 leased line adapters (sbni), allowing
    local users to perform privileged operations.
CVE-2008-3831
    Olaf Kirch discovered an issue with the i915 driver that may allow
    local users to cause memory corruption by use of an ioctl with
    insufficient privilege restrictions.
    Eugene Teo discovered two issues in the SCTP subsystem which allow
    local users to obtain access to sensitive memory when the
    SCTP-AUTH extension is enabled.
For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1655');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1655] DSA-1655-1 linux-2.6.24");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1655-1 linux-2.6.24");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
