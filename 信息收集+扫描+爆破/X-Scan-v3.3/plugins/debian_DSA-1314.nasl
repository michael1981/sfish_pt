# This script was automatically generated from the dsa-1314
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25558);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1314");
 script_cve_id("CVE-2007-3099", "CVE-2007-3100");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1314 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in
open-iscsi, a transport-independent iSCSI implementation. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-3099
    Olaf Kirch discovered that due to a programming error access to the
    management interface socket was insufficiently protected, which allows
    denial of service.
CVE-2007-3100
    Olaf Kirch discovered that access to a semaphore used in the logging
    code was insufficiently protected, allowing denial of service.
The oldstable distribution (sarge) doesn\'t include open-iscsi.
For the stable distribution (etch) these problems have been fixed
in version 2.0.730-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1314');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your open-iscsi packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1314] DSA-1314-1 open-iscsi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1314-1 open-iscsi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'open-iscsi', release: '4.0', reference: '2.0.730-1etch1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
