# This script was automatically generated from the dsa-1505
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31149);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1505");
 script_cve_id("CVE-2007-4571");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1505 security update');
 script_set_attribute(attribute: 'description', value:
'Takashi Iwai supplied a fix for a memory leak in the snd_page_alloc module.
Local users could exploit this issue to obtain sensitive information from
the kernel (CVE-2007-4571).
For the oldstable distribution (sarge), this problem has been fixed in
version 1.0.8-7sarge1. The prebuilt modules provided by alsa-modules-i386
have been rebuilt to take advantage of this update, and are available in
version 1.0.8+2sarge2.
For the stable distribution (etch), this problem has been fixed in
version 1.0.13-5etch1. This issue was already fixed for the version
of ALSA provided by linux-2.6 in DSA 1479.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1505');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your alsa-driver and alsa-modules-i386
packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1505] DSA-1505-1 alsa-driver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1505-1 alsa-driver");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'alsa-base', release: '3.1', reference: '1.0.8-7sarge1');
deb_check(prefix: 'alsa-headers', release: '3.1', reference: '1.0.8-7sarge1');
deb_check(prefix: 'alsa-modules-2.4-386', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-586tsc', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-686', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-686-smp', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-k6', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-k7', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4-k7-smp', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-386', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-586tsc', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-686', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-686-smp', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-k6', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-k7', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-modules-2.4.27-4-k7-smp', release: '3.1', reference: '1.0.8+2sarge2');
deb_check(prefix: 'alsa-source', release: '3.1', reference: '1.0.8-7sarge1');
deb_check(prefix: 'alsa-base', release: '4.0', reference: '1.0.13-5etch1');
deb_check(prefix: 'alsa-source', release: '4.0', reference: '1.0.13-5etch1');
deb_check(prefix: 'linux-sound-base', release: '4.0', reference: '1.0.13-5etch1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
