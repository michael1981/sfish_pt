# This script was automatically generated from the dsa-1002
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22544);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1002");
 script_cve_id("CVE-2005-3949", "CVE-2005-3961", "CVE-2005-3982");
 script_bugtraq_id(15606, 15608, 15662, 15673);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1002 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in webcalendar,
a PHP based multi-user calendar.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
CVE-2005-3949
    Multiple SQL injection vulnerabilities allow remote attackers to
    execute arbitrary SQL commands.
CVE-2005-3961
    Missing input sanitising allows an attacker to overwrite local
    files.
CVE-2005-3982
    A CRLF injection vulnerability allows remote attackers to modify
    HTTP headers and conduct HTTP response splitting attacks.
The old stable distribution (woody) does not contain webcalendar packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.45-4sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1002');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webcalendar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1002] DSA-1002-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1002-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
