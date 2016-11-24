#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12631);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0378");

 script_name(english:"RHSA-2002-120: LPRng");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-120");
 
 script_set_attribute(attribute:"description", value:
'
  The LPRng print spooler, as shipped in Red Hat Linux Advanced Server 2.1,
  accepts all remote print jobs by default. Updated LPRng packages are
  available to fix this issue.

  With its default configuration, LPRng will accept job submissions from
  any host, which is not appropriate in a workstation environment. We
  are grateful to Matthew Caron for pointing out this configuration
  problem.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0378 to this issue.

  The updated packages from this advisory change the job submission
  policy (in /etc/lpd.perms) so that jobs from remote hosts are refused
  by default.

  Those running print servers may want to adjust this policy as
  appropriate, for example to give access to certain hosts or subnets.
  For details on how to do this, see the lpd.perms(5) man page.

  Please note that default installations of Red Hat Linux Advanced Server 2.1
  include ipchains rules blocking remote access to the print spooler IP port;
  as a result those installations already reject remote job submissions.

  NOTE: There are special instructions for installing this update at
  the end of the "Solution" section.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-120.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the LPRng packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"LPRng-3.7.4-28.1", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
