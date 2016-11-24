# This script was automatically generated from the dsa-177
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(15014);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "177");
 script_cve_id("CVE-2002-1227");

  script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-177 security update.");
  script_set_attribute(attribute: "description", value: 
'A serious security violation in PAM was discovered.
Disabled passwords (i.e. those with \'*\' in the
password file) were classified as empty password and access to such
accounts is granted through the regular login procedure (getty,
telnet, ssh).  This works for all such accounts whose shell field in
the password file does not refer to /bin/false.
Only version 0.76 of PAM seems to be affected by this problem.
This problem has been fixed in version 0.76-6 for the current unstable
distribution (sid).  The stable distribution (woody), the old stable
distribution (potato) and the testing distribution (sarge) are not
affected by this problem.
As stated in the Debian security team FAQ, testing
and unstable are rapidly moving targets and the security team does not
have the resources needed to properly support those.  This security
advisory is an exception to that rule, due to the seriousness of the
problem.');
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2002/dsa-177");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2002/dsa-177 
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();

 script_copyright(english: "This script is (C) 2005-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA177] DSA-177-1 pam");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-177-1 pam");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-cracklib', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-cracklib is vulnerable in Debian 3.2.\nUpgrade to libpam-cracklib_0.76-6\n');
}
if (deb_check(prefix: 'libpam-doc', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-doc is vulnerable in Debian 3.2.\nUpgrade to libpam-doc_0.76-6\n');
}
if (deb_check(prefix: 'libpam-modules', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-modules is vulnerable in Debian 3.2.\nUpgrade to libpam-modules_0.76-6\n');
}
if (deb_check(prefix: 'libpam-runtime', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-runtime is vulnerable in Debian 3.2.\nUpgrade to libpam-runtime_0.76-6\n');
}
if (deb_check(prefix: 'libpam0g', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam0g is vulnerable in Debian 3.2.\nUpgrade to libpam0g_0.76-6\n');
}
if (deb_check(prefix: 'libpam0g-dev', release: '3.2', reference: '0.76-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam0g-dev is vulnerable in Debian 3.2.\nUpgrade to libpam0g-dev_0.76-6\n');
}
if (w) { security_hole(port: 0, extra: desc); }
