# This script was automatically generated from the dsa-815
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19711);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "815");
 script_cve_id("CVE-2005-2494");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-815 security update');
 script_set_attribute(attribute: 'description', value:
'Ilja van Sprundel discovered a serious lock file handling error in
kcheckpass that can, in some configurations, be used to gain root
access.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-815');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdebase-bin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA815] DSA-815-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-815-1 kdebase");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kappfinder', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kate', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kcontrol', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase-bin', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase-data', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase-dev', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase-doc', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdebase-kio-plugins', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdepasswd', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdeprint', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdesktop', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kdm', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kfind', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'khelpcenter', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kicker', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'klipper', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kmenuedit', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'konqueror', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'konqueror-nsplugins', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'konsole', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kpager', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kpersonalizer', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'ksmserver', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'ksplash', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'ksysguard', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'ksysguardd', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'ktip', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'kwin', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'libkonq4', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'libkonq4-dev', release: '3.1', reference: '3.3.2-1sarge1');
deb_check(prefix: 'xfonts-konsole', release: '3.1', reference: '3.3.2-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
