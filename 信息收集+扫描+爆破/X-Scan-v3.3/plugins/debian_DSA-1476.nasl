# This script was automatically generated from the dsa-1476
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30111);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1476");
 script_cve_id("CVE-2008-0008");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1476 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner discovered that the PulseAudio sound server performed
insufficient checks when dropping privileges, which could lead to local
privilege escalation.
The old stable distribution (sarge) doesn\'t contain pulseaudio.
For the stable distribution (etch), this problem has been fixed in
version 0.9.5-5etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1476');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pulseaudio packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1476] DSA-1476-1 pulseaudio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1476-1 pulseaudio");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpulse-browse0', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'libpulse-dev', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'libpulse-mainloop-glib0', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'libpulse0', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-esound-compat', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-gconf', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-hal', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-jack', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-lirc', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-x11', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-module-zeroconf', release: '4.0', reference: '0.9.5-5etch1');
deb_check(prefix: 'pulseaudio-utils', release: '4.0', reference: '0.9.5-5etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
