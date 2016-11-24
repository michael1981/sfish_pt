# This script was automatically generated from the dsa-778
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19475);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "778");
 script_cve_id("CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090");
 script_bugtraq_id(14604);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-778 security update');
 script_set_attribute(attribute: 'description', value:
'Two security related problems have been discovered in Mantis, a
web-based bug tracking system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    A remote attacker could supply a specially crafted URL to scan
    arbitrary ports on arbitrary hosts that may not be accessible
    otherwise.
    A remote attacker was able to insert arbitrary HTML code in bug
    reports, hence, cross site scripting.
    A remote attacker was able to insert arbitrary HTML code in bug
    reports, hence, cross site scripting.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-778');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA778] DSA-778-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-778-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
