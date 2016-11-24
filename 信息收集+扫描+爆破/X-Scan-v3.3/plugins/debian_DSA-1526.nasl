# This script was automatically generated from the dsa-1526
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31632);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1526");
 script_cve_id("CVE-2008-0930", "CVE-2008-0931");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1526 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp from the Debian Security Audit project discovered several local
vulnerabilities in xwine, a graphical user interface for the WINE emulator.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-0930
  The xwine command makes unsafe use of local temporary files when
  printing.  This could allow the removal of arbitrary files belonging
  to users who invoke the program.
CVE-2008-0931
  The xwine command changes the permissions of the global WINE configuration
  file such that it is world-writable.  This could allow local users to edit
  it such that arbitrary commands could be executed whenever any local user
  executed a program under WINE.
For the stable distribution (etch), these problems have been fixed in version
1.0.1-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1526');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xwine package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1526] DSA-1526-1 xwine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1526-1 xwine");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xwine', release: '4.0', reference: '1.0.1-1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
