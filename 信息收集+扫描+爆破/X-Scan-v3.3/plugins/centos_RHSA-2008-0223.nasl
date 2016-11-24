#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(31999);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2008-0223");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2008-0223.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2008-0223.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_end_attributes();

script_cve_id("CVE-2008-1380");

 script_summary(english:"Checks for missing updates on the remote CentOS system");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/CentOS/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/CentOS/rpm-list") ) exit(1, "Could not obtain the list of packages");

if ( rpm_check(reference:"seamonkey-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-0.17.el3.centos3", release:"CentOS-3", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-chat-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-mail-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.9-16.el4.centos", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
