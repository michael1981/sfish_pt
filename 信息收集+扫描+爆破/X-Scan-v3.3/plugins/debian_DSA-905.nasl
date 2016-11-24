# This script was automatically generated from the dsa-905
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22771);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "905");
 script_cve_id("CVE-2005-3091", "CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3338", "CVE-2005-3339");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-905 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mantis, a
web-based bug tracking system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2005-3091
    A cross-site scripting vulnerability allows attackers to inject
    arbitrary web script or HTML.
CVE-2005-3335
    A file inclusion vulnerability allows remote attackers to execute
    arbitrary PHP code and include arbitrary local files.
CVE-2005-3336
    An SQL injection vulnerability allows remote attackers to execute
    arbitrary SQL commands.
CVE-2005-3338
    Mantis can be tricked into displaying the otherwise hidden real
    mail address of its users.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-4.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-905');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA905] DSA-905-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-905-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
