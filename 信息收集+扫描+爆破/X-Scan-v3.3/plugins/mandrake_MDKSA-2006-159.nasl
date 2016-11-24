
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23903);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:159: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:159 (sudo).");
 script_set_attribute(attribute: "description", value: "Previous sudo updates were made available to sanitize certain
environment variables from affecting a sudo call, such as
PYTHONINSPECT, PERL5OPT, etc. While those updates were effective in
addressing those specific environment variables, other variables that
were not blacklisted were being made available.
Debian addressed this issue by forcing sudo to use a whitlist approach
in DSA-946-2 by arbitrarily making env_reset the default (as opposed
to having to be enabled in /etc/sudoers). Mandriva has opted to follow
the same approach so now only certain variables are, by default, made
available, such as HOME, LOGNAME, SHELL, TERM, DISPLAY, XAUTHORITY,
XAUTHORIZATION, LANG, LANGUAGE, LC_*, and USER, as well as the SUDO_*
variables.
If other variables are required to be kept, this can be done by editing
/etc/sudoers and using the env_keep option, such as:
Defaults env_keep='FOO BAR'
As well, the Corporate 3 packages are now compiled with the SECURE_PATH
setting.
Updated packages are patched to address this issue.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:159");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the sudo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sudo-1.6.8p8-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
