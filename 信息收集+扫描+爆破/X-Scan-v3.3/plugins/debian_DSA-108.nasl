# This script was automatically generated from the dsa-108
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14945);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "108");
 script_cve_id("CVE-2002-0247", "CVE-2002-0248");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-108 security update');
 script_set_attribute(attribute: 'description', value:
'Nicolas Boullis found some security problems in the wmtv package (a
dockable video4linux TV player for windowmaker) which is distributed
in Debian GNU/Linux 2.2.  With the current version of wmtv, the
configuration file is written back as the superuser, and without any
further checks.  A malicious user might use that to damage important
files.
This problem has been fixed in version 0.6.5-2potato2 for the stable
distribution by dropping privileges as soon as possible and only
regaining them where required.  In the current testing/unstable
distribution this problem has been fixed in version 0.6.5-9 and above
by not requiring privileges anymore.  Both contain fixes for two
potential buffer overflows as well.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-108');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wmtv packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA108] DSA-108-1 wmtv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-108-1 wmtv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wmtv', release: '2.2', reference: '0.6.5-2potato2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
