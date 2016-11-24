# This script was automatically generated from the dsa-1811
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38992);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1811");
 script_cve_id("CVE-2009-0949");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1811 security update');
 script_set_attribute(attribute: 'description', value:
'Anibal Sacco discovered that cups, a general printing system for UNIX
systems, suffers from null pointer dereference because of its handling
of two consecutive IPP packets with certain tag attributes that are
treated as IPP_TAG_UNSUPPORTED tags. This allows unauthenticated attackers
to perform denial of service attacks by crashing the cups daemon.
For the oldstable distribution (etch), this problem has been fixed in
version 1.2.7-4+etch8 of cupsys.
For the stable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny6 of cups.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1811');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cups/cupsys packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1811] DSA-1811-1 cups, cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1811-1 cups, cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'cupsys-bsd', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'cupsys-client', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'cupsys-common', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'cupsys-dbg', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'libcupsimage2', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'libcupsimage2-dev', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'libcupsys2', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'libcupsys2-dev', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'libcupsys2-gnutls10', release: '4.0', reference: '1.2.7-4+etch8');
deb_check(prefix: 'cups', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cups-bsd', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cups-client', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cups-common', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cups-dbg', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cupsys', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cupsys-bsd', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cupsys-client', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cupsys-common', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'cupsys-dbg', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcups2', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcups2-dev', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcupsimage2', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcupsimage2-dev', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcupsys2', release: '5.0', reference: '1.3.8-1+lenny6');
deb_check(prefix: 'libcupsys2-dev', release: '5.0', reference: '1.3.8-1+lenny6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
