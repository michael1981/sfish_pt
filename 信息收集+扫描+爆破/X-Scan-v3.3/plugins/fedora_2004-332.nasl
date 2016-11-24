#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15454);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0884");
 
 name["english"] = "Fedora Core 2 2004-332: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-332 (cyrus-sasl).

The cyrus-sasl package contains the Cyrus implementation of SASL.
SASL is the Simple Authentication and Security Layer, a method for
adding authentication support to connection-based protocols.

Update Information:

At application startup, libsasl and libsasl2 attempt to build a list
of all SASL plug-ins which are available on the system.  To do so,
the libraries search for and attempt to load every shared library
found within the plug-in directory.  This location can be set with
the SASL_PATH environment variable.

In situations where an untrusted local user can affect the
environment of a privileged process, this behavior could be exploited
to run arbitrary code with the privileges of a setuid or setgid
application.  The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0884 to this issue.

Users of cyrus-sasl should upgrade to these updated packages, which
contain backported patches and are not vulnerable to this issue." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-332.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the cyrus-sasl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-sasl-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-devel-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-md5-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-debuginfo-2.1.18-2.2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"cyrus-sasl-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0884", value:TRUE);
}
