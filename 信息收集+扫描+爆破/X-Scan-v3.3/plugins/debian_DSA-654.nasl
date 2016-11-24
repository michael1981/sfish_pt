# This script was automatically generated from the dsa-654
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16238);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "654");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-654 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund has discovered several security relevant problems in
enscript, a program to convert ASCII text into Postscript and other
formats.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
    Unsanitised input can cause the execution of arbitrary commands
    via EPSF pipe support.  This has been disabled, also upstream.
    Due to missing sanitising of filenames it is possible that a
    specially crafted filename can cause arbitrary commands to be
    executed.
    Multiple buffer overflows can cause the program to crash.
Usually, enscript is only run locally, but since it is executed inside
of viewcvs some of the problems mentioned above can easily be turned
into a remote vulnerability.
For the stable distribution (woody) these problems have been fixed in
version 1.6.3-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-654');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your enscript package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA654] DSA-654-1 enscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-654-1 enscript");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'enscript', release: '3.0', reference: '1.6.3-1.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
