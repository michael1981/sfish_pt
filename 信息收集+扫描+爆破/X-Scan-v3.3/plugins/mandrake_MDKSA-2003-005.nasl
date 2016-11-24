
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13990);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2003:005: leafnode");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:005 (leafnode).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by Jan Knutar in leafnode that
Mark Brown pointed out could be used in a Denial of Service
attack. This vulnerability causes leafnode to go into an
infinite loop with 100% CPU use when an article that has been
crossposed to several groups, one of which is the prefix of
another, is requested by it's Message-ID.
This vulnerability was introduced in 1.9.20 and fixed upstream
in version 1.9.30. Only Mandrake Linux 9.0 is affected by this,
but version 1.9.19 (which shipped with Mandrake Linux 8.2) is
receiving an update due to critical bugs in it that can corrupt
parts of its news spool under certain circumstances.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:005");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the leafnode package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"leafnode-1.9.31-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"leafnode-1.9.31-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
