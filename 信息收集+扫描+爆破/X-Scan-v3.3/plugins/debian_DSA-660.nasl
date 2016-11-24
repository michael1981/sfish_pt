# This script was automatically generated from the dsa-660
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16262);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "660");
 script_cve_id("CVE-2005-0078");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-660 security update');
 script_set_attribute(attribute: 'description', value:
'Raphaël Enrici discovered that the KDE screensaver can crash under
certain local circumstances.  This can be exploited by an attacker
with physical access to the workstation to take over the desktop
session.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-660');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kscreensaver package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA660] DSA-660-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-660-1 kdebase");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.9');
deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
