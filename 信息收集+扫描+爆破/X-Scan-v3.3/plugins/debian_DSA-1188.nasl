# This script was automatically generated from the dsa-1188
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22730);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1188");
 script_cve_id("CVE-2006-3636", "CVE-2006-4624");
 script_bugtraq_id(19831);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1188 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in mailman, the
web-based GNU mailing list manager.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2006-3636
    Moritz Naumann discovered several cross-site scripting problems
    that could allow remote attackers to inject arbitrary web script code
    or HTML.
CVE-2006-4624
    Moritz Naumann discovered that a remote attacker can inject
    arbitrary strings into the logfile.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.5-8sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1188');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mailman package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1188] DSA-1188-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1188-1 mailman");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
