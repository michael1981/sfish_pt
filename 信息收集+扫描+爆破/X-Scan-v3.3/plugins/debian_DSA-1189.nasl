# This script was automatically generated from the dsa-1189
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22731);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1189");
 script_cve_id("CVE-2006-4924", "CVE-2006-5051");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1189 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in OpenSSH, a free
implementation of the Secure Shell protocol, which may lead to denial of
service and potentially the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2006-4924
    Tavis Ormandy of the Google Security Team discovered a denial of
    service vulnerability in the mitigation code against complexity
    attacks, which might lead to increased CPU consumption until a
    timeout is triggered. This is only exploitable if support for 
    SSH protocol version 1 is enabled.
CVE-2006-5051
    Mark Dowd discovered that insecure signal handler usage could
    potentially lead to execution of arbitrary code through a double
    free. The Debian Security Team doesn\'t believe the general openssh
    package without Kerberos support to be exploitable by this issue.
    However, due to the complexity of the underlying code we will
    issue an update to rule out all eventualities.
For the stable distribution (sarge) these problems have been fixed in
version 3.8.1p1-7sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1189');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssh-krb5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1189] DSA-1189-1 openssh-krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1189-1 openssh-krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh-krb5', release: '3.1', reference: '3.8.1p1-7sarge1');
deb_check(prefix: 'openssh-krb5', release: '3.1', reference: '3.8.1p1-7sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
