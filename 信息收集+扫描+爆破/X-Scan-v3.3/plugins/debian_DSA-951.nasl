# This script was automatically generated from the dsa-951
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22817);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "951");
 script_cve_id("CVE-2005-4065", "CVE-2005-4644");
 script_bugtraq_id(15720, 16198);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-951 security update');
 script_set_attribute(attribute: 'description', value:
'This update corrects the search feature in trac, an enhanced wiki
and issue tracking system for software development projects, which
broke with the last security update.  For completeness please find
below the original advisory text:
Several vulnerabilities have been discovered in trac, an enhanced wiki
and issue tracking system for software development projects.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2005-4065
    Due to missing input sanitising it is possible to inject arbitrary
    SQL code into the SQL statements.
CVE-2005-4644
    A cross-site scripting vulnerability has been discovered that
    allows remote attackers to inject arbitrary web script or HTML.
The old stable distribution (woody) does not contain trac packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.1-3sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-951');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your trac package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA951] DSA-951-2 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-951-2 trac");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
