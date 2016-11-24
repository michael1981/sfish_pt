# This script was automatically generated from the dsa-1681
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35036);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1681");
 script_cve_id("CVE-2008-3528", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1681 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-3528
    Eugene Teo reported a local DoS issue in the ext2 and ext3
    filesystems.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that causes the kernel to output error messages in an
    infinite loop.
CVE-2008-4554
    Milos Szeredi reported that the usage of splice() on files opened
    with O_APPEND allows users to write to the file at arbitrary
    offsets, enabling a bypass of possible assumed semantics of the
    O_APPEND flag.
CVE-2008-4576
    Vlad Yasevich reported an issue in the SCTP subsystem that may
    allow remote users to cause a local DoS by triggering a kernel
    oops.
CVE-2008-4618
    Wei Yongjun reported an issue in the SCTP subsystem that may allow
    remote users to cause a local DoS by triggering a kernel panic.
CVE-2008-4933
    Eric Sesterhenn reported a local DoS issue in the hfsplus
    filesystem.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that causes the kernel to overrun a buffer, resulting
    in a system oops or memory corruption.
CVE-2008-4934
    Eric Sesterhenn reported a local DoS issue in the hfsplus
    filesystem.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that results in a kernel oops due to an unchecked
    return value.
CVE-2008-5025
    Eric Sesterhenn reported a local DoS issue in the hfs filesystem.
    Local users who have been granted the privileges necessary to
    mount a filesystem would be able to craft a filesystem with a
    corrupted catalog name length, resulting in a system oops or
    memory corruption.
CVE-2008-5029
    Andrea Bittau reported a DoS issue in the unix socket subsystem
    that allows a local user to cause memory corruption, resulting in
    a kernel panic.
CVE-2008-5134
    Johannes Berg reported a remote DoS issue in the libertas wireless
    driver, which can be triggered by a specially crafted beacon/probe
    response.
CVE-2008-5182
    Al Viro reported race conditions in the inotify subsystem that may
    allow local users to acquire elevated privileges.
CVE-2008-5300
    Dann Frazier reported a DoS condition that allows local users to
    cause the out of memory handler to kill off privileged processes
    or trigger soft lockups due to a starvation issue in the unix
    socket subsystem.
For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1681');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1681] DSA-1681-1 linux-2.6.24");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1681-1 linux-2.6.24");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
