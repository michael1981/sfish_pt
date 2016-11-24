# This script was automatically generated from the dsa-967
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22833);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "967");
 script_cve_id("CVE-2005-4439", "CVE-2006-0347", "CVE-2006-0348", "CVE-2006-0597", "CVE-2006-0598", "CVE-2006-0599", "CVE-2006-0600");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-967 security update');
 script_set_attribute(attribute: 'description', value:
'Several security problems have been found in elog, an electronic logbook
to manage notes.  The Common Vulnerabilities and Exposures Project
identifies the following problems:
CVE-2005-4439
    "GroundZero Security" discovered that elog insufficiently checks the
    size of a buffer used for processing URL parameters, which might lead
    to the execution of arbitrary code.
CVE-2006-0347
    It was discovered that elog contains a directory traversal vulnerability
    in the processing of "../" sequences in URLs, which might lead to
    information disclosure.
CVE-2006-0348
    The code to write the log file contained a format string vulnerability,
    which might lead to the execution of arbitrary code.
CVE-2006-0597
    Overly long revision attributes might trigger a crash due to a buffer
    overflow.
CVE-2006-0598
    The code to write the log file does not enforce bounds checks properly,
    which might lead to the execution of arbitrary code.
CVE-2006-0599
    elog emitted different errors messages for invalid passwords and invalid
    users, which allows an attacker to probe for valid user names.
CVE-2006-0600
    An attacker could be driven into infinite redirection with a crafted
    "fail" request, which has denial of service potential.
The old stable distribution (woody) does not contain elog packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.5.7+r1558-4+sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-967');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your elog package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA967] DSA-967-1 elog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-967-1 elog");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'elog', release: '3.1', reference: '2.5.7+r1558-4+sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
