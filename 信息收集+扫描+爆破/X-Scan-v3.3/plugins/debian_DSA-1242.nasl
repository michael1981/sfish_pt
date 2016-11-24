# This script was automatically generated from the dsa-1242
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23947);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1242");
 script_cve_id("CVE-2006-5063", "CVE-2006-5790", "CVE-2006-5791", "CVE-2006-6318");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1242 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in elog, a web-based
electronic logbook, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-5063
    Tilman Koschnick discovered that log entry editing in HTML is vulnerable
    to cross-site scripting. This update disables the vulnerable code.
CVE-2006-5790
    Ulf Härnhammar of the Debian Security Audit Project discovered several
    format string vulnerabilities in elog, which may lead to execution of
    arbitrary code.
CVE-2006-5791
    Ulf Härnhammar of the Debian Security Audit Project discovered 
    cross-site scripting vulnerabilities in the creation of new logbook
    entries.
CVE-2006-6318
    Jayesh KS and Arun Kethipelly of OS2A discovered that elog performs
    insufficient error handling in config file parsing, which may lead to
    denial of service through a NULL pointer dereference.
For the stable distribution (sarge) these problems have been fixed in
version 2.5.7+r1558-4+sarge3.
The upcoming stable distribution (etch) will no longer include elog.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1242');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your elog package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1242] DSA-1242-1 elog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1242-1 elog");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'elog', release: '3.1', reference: '2.5.7+r1558-4+sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
