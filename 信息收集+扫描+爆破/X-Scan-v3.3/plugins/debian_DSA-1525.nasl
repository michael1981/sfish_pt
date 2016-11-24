# This script was automatically generated from the dsa-1525
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31631);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1525");
 script_cve_id("CVE-2007-6430", "CVE-2008-1332", "CVE-2008-1333");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1525 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Asterisk, a free
software PBX and telephony toolkit. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-6430
    Tilghman Lesher discovered that database-based registrations are
    insufficiently validated. This only affects setups, which are
    configured to run without a password and only host-based
    authentication.
CVE-2008-1332
    Jason Parker discovered that insufficient validation of From:
    headers inside the SIP channel driver may lead to authentication
    bypass and the potential external initiation of calls.
CVE-2008-1333
    This update also fixes a format string vulnerability, which can only be
    triggered through configuration files under control of the local
    administrator. In later releases of Asterisk this issue is remotely
    exploitable and tracked as <a
    href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1333">CVE-2008-1333</a>.
The status of the old stable distribution (sarge) is currently being
investigated. If affected, an update will be released through
security.debian.org.
For the stable distribution (etch), these problems have been fixed in
version 1:1.2.13~dfsg-2etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1525');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your asterisk packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1525] DSA-1525-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1525-1 asterisk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
