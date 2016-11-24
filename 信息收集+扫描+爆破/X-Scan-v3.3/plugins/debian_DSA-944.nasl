# This script was automatically generated from the dsa-944
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22810);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "944");
 script_cve_id("CVE-2005-4238", "CVE-2005-4518", "CVE-2005-4519", "CVE-2005-4520", "CVE-2005-4521", "CVE-2005-4522", "CVE-2005-4523");
 script_bugtraq_id(15842, 16046);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-944 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mantis, a
web-based bug tracking system. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2005-4238
    Missing input sanitising allows remote attackers  to inject
    arbitrary web script or HTML.
CVE-2005-4518
    Tobias Klein discovered that Mantis allows remote attackers to
    bypass the file upload size restriction.
CVE-2005-4519
    Tobias Klein discovered several SQL injection vulnerabilities that
    allow remote attackers to execute arbitrary SQL commands.
CVE-2005-4520
    Tobias Klein discovered unspecified "port injection"
    vulnerabilities in filters.
CVE-2005-4521
    Tobias Klein discovered a CRLF injection vulnerability that allows
    remote attackers to modify HTTP headers and conduct HTTP response
    splitting attacks.
CVE-2005-4522
    Tobias Klein discovered several cross-site scripting (XSS)
    vulnerabilities that allow remote attackers to inject arbitrary
    web script or HTML.
CVE-2005-4523
    Tobias Klein discovered that Mantis discloses private bugs via
    public RSS feeds, which allows remote attackers to obtain
    sensitive information.
CVE-2005-4524
    Tobias Klein discovered that Mantis does not properly handle "Make
    note private" when a bug is being resolved, which has unknown
    impact and attack vectors, probably related to an information
    leak.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-5sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-944');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA944] DSA-944-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-944-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
