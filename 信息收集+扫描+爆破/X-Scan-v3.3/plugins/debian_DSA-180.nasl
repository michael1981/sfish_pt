# This script was automatically generated from the dsa-180
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15017);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "180");
 script_cve_id("CVE-2002-1232");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-180 security update');
 script_set_attribute(attribute: 'description', value:
'Thorsten Kukuck discovered a problem in the ypserv program which is
part of the Network Information Services (NIS).  A memory leak in all
versions of ypserv prior to 2.5 is remotely exploitable.  When a
malicious user could request a non-existing map the server will leak
parts of an old domainname and mapname.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-180');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA180] DSA-180-1 nis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-180-1 nis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nis', release: '2.2', reference: '3.8-2.1');
deb_check(prefix: 'nis', release: '3.0', reference: '3.9-6.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
