# This script was automatically generated from the dsa-946
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22812);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "946");
 script_cve_id("CVE-2005-4158", "CVE-2006-0151");
 script_bugtraq_id(16184);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-946 security update');
 script_set_attribute(attribute: 'description', value:
'The former correction to vulnerabilities in the sudo package worked
fine but were too strict for some environments.  Therefore we have
reviewed the changes again and allowed some environment variables to
go back into the privileged execution environment.  Hence, this
update.
The configuration option "env_reset" is now activated by default.
It will preserve only the environment variables HOME, LOGNAME, PATH,
SHELL, TERM, DISPLAY, XAUTHORITY, XAUTHORIZATION, LANG, LANGUAGE,
LC_*, and USER in addition to the separate SUDO_* variables.
For completeness please find below the original advisory text:
It has been discovered that sudo, a privileged program, that provides
limited super user privileges to specific users, passes several
environment variables to the program that runs with elevated
privileges.  In the case of include paths (e.g. for Perl, Python, Ruby
or other scripting languages) this can cause arbitrary code to be
executed as privileged user if the attacker points to a manipulated
version of a system library.
This update alters the former behaviour of sudo and limits the number
of supported environment variables to LC_*, LANG, LANGUAGE and TERM.
Additional variables are only passed through when set as env_check in
/etc/sudoers, which might be required for some scripts to continue to
work.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.6.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-946');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sudo package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA946] DSA-946-2 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-946-2 sudo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sudo', release: '3.0', reference: '1.6.6-1.6');
deb_check(prefix: 'sudo', release: '3.1', reference: '1.6.8p7-1.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
