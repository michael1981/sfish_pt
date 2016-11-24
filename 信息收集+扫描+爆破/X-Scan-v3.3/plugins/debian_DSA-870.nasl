# This script was automatically generated from the dsa-870
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22736);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "870");
 script_cve_id("CVE-2005-2959");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-870 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy noticed that sudo, a program that provides limited super
user privileges to specific users, does not clean the environment
sufficiently.  The SHELLOPTS and PS4 variables are dangerous and are
still passed through to the program running as privileged user.  This
can result in the execution of arbitrary commands as privileged user
when a bash script is executed.  These vulnerabilities can only be
exploited by users who have been granted limited super user
privileges.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.4.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-870');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sudo package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA870] DSA-870-1 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-870-1 sudo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.4');
deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
