# This script was automatically generated from the dsa-232
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15069);
 script_version("$Revision: 1.16 $");
 script_xref(name: "DSA", value: "232");
 script_bugtraq_id(6435);
 script_bugtraq_id(6436);
 script_bugtraq_id(6437);
 script_bugtraq_id(6438);
 script_bugtraq_id(6439);
 script_bugtraq_id(6440);
 script_bugtraq_id(6475);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-232 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities were discovered in the Common Unix Printing
System (CUPS).  Several of these issues represent the potential for a
remote compromise or denial of service.  The Common Vulnerabilities
and Exposures project identifies the following problems:
Even though we tried very hard to fix all problems in the packages for
potato as well, the packages may still contain other security related
problems.  Hence, we advise users of potato systems using CUPS to
upgrade to woody soon.
For the current stable distribution (woody), these problems have been fixed
in version 1.1.14-4.3.
For the old stable distribution (potato), these problems have been fixed
in version 1.0.4-12.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-232');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your CUPS packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA232] DSA-232-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
 script_summary(english: "DSA-232-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.1');
deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-12.1');
deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-12.1');
deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-12.1');
deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-4.4');
deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-4.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
