# This script was automatically generated from the dsa-1636
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34171);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1636");
 script_cve_id("CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3276", "CVE-2008-3526", "CVE-2008-3534", "CVE-2008-3535", "CVE-2008-3792");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1636 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that may
lead to a denial of service or leak sensitive data. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2008-3272
    Tobias Klein reported a locally exploitable data leak in the
    snd_seq_oss_synth_make_info() function. This may allow local users
    to gain access to sensitive information.
CVE-2008-3275
    Zoltan Sogor discovered a coding error in the VFS that allows local users
    to exploit a kernel memory leak resulting in a denial of service.
CVE-2008-3276
    Eugene Teo reported an integer overflow in the DCCP subsystem that
    may allow remote attackers to cause a denial of service in the form
    of a kernel panic.
CVE-2008-3526
    Eugene Teo reported a missing bounds check in the SCTP subsystem.
    By exploiting an integer overflow in the SCTP_AUTH_KEY handling code,
    remote attackers may be able to cause a denial of service in the form
    of a kernel panic.
CVE-2008-3534
    Kel Modderman reported an issue in the tmpfs filesystem that allows
    local users to crash a system by triggering a kernel BUG() assertion.
CVE-2008-3535
    Alexey Dobriyan discovered an off-by-one-error in the iov_iter_advance
    function which can be exploited by local users to crash a system,
    resulting in a denial of service.
CVE-2008-3792
    Vlad Yasevich reported several NULL pointer reference conditions in
    the SCTP subsystem that can be triggered by entering sctp-auth codepaths
    when the AUTH feature is inactive. This may allow attackers to cause
    a denial of service condition via a system panic.
CVE-2008-3915
    Johann Dahm and David Richter reported an issue in the nfsd subsystem
    that may allow remote attackers to cause a denial of service via a
    buffer overflow.
For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1636');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1636] DSA-1636-1 linux-2.6.24");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1636-1 linux-2.6.24");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
