
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34320);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  dovecot security update (dovecot-5647)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch dovecot-5647");
 script_set_attribute(attribute: "description", value: "When configured with 'mail_extra_groups' dovecot
potentially allowed users to read mail boxes of other
users. This is not the case in the default configuration of
on openSUSE (CVE-2008-1199).

By using tab characters in passwords remote attackers could
potentially acquire unauthorized access (CVE-2008-1218).

Flaws in caching LDAP data could lead to users getting
logged in with the wrong account (CVE-2007-6598).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch dovecot-5647");
script_end_attributes();

script_cve_id("CVE-2008-1199", "CVE-2008-1218", "CVE-2007-6598");
script_summary(english: "Check for the dovecot-5647 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dovecot-1.0.5-6.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dovecot-devel-1.0.5-6.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
