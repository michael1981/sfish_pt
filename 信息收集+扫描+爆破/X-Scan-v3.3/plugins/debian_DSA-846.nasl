# This script was automatically generated from the dsa-846
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19954);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "846");
 script_cve_id("CVE-2005-1111", "CVE-2005-1229");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-846 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in cpio, a program to manage
archives of files.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Imran Ghory discovered a race condition in setting the file
    permissions of files extracted from cpio archives.  A local
    attacker with write access to the target directory could exploit
    this to alter the permissions of arbitrary files the extracting
    user has write permissions for.
    Imran Ghory discovered that cpio does not sanitise the path of
    extracted files even if the --no-absolute-filenames option was
    specified.  This can be exploited to install files in arbitrary
    locations where the extracting user has write permissions to.
For the old stable distribution (woody) these problems have been fixed in
version 2.4.2-39woody2.
For the stable distribution (sarge) these problems have been fixed in
version 2.5-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-846');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cpio package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA846] DSA-846-1 cpio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-846-1 cpio");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody2');
deb_check(prefix: 'cpio', release: '3.1', reference: '2.5-1.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
