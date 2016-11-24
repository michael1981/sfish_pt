# This script was automatically generated from the dsa-973
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22839);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "973");
 script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");
 script_bugtraq_id(15537);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-973 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in otrs, the Open Ticket
Request System, that can be exploited remotely.  The Common
Vulnerabilities and Exposures Project identifies the following
problems:
CVE-2005-3893
    Multiple SQL injection vulnerabilities allow remote attackers to
    execute arbitrary SQL commands and bypass authentication.
CVE-2005-3894
    Multiple cross-site scripting vulnerabilities allow remote
    authenticated users to inject arbitrary web script or HTML.
CVE-2005-3895
    Internally attached text/html mails are rendered as HTML when the
    queue moderator attempts to download the attachment, which allows
    remote attackers to execute arbitrary web script or HTML.
The old stable distribution (woody) does not contain OTRS packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.2p01-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-973');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your otrs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA973] DSA-973-1 otrs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-973-1 otrs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'otrs', release: '3.1', reference: '1.3.2p01-6');
deb_check(prefix: 'otrs-doc-de', release: '3.1', reference: '1.3.2p01-6');
deb_check(prefix: 'otrs-doc-en', release: '3.1', reference: '1.3.2p01-6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
