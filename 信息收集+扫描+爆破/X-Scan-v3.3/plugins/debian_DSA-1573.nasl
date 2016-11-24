# This script was automatically generated from the dsa-1573
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32307);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1573");
 script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1573 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in rdesktop, a
Remote Desktop Protocol client. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2008-1801
    Remote exploitation of an integer underflow vulnerability allows
    attackers to execute arbitrary code with the privileges of the
    logged-in user.
CVE-2008-1802
    Remote exploitation of a BSS overflow vulnerability allows
    attackers to execute arbitrary code with the privileges of the
    logged-in user.
CVE-2008-1803
    Remote exploitation of an integer signedness vulnerability allows
    attackers to execute arbitrary code with the privileges of the
    logged-in user.
For the stable distribution (etch), these problems have been fixed in
version 1.5.0-1etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1573');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your rdesktop package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1573] DSA-1573-1 rdesktop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1573-1 rdesktop");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rdesktop', release: '4.0', reference: '1.5.0-1etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
