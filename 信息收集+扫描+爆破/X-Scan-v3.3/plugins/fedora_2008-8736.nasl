
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8736
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34379);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-8736: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8736 (ruby)");
 script_set_attribute(attribute: "description", value: "Ruby is the interpreted scripting language for quick and easy
object-oriented programming.  It has many features to process text
files and to do system management tasks (as in Perl).  It is simple,
straight-forward, and extensible.

-
Update Information:

Update to new upstream release fixing multiple security issues detailed in the
upstream advisories:    [9]http://www.ruby-lang.org/en/news/2008/08/08/multiple
-
vulnerabilities-in-ruby/  - CVE-2008-3655 - multiple insufficient safe mode
restrictions  - CVE-2008-3656 - WEBrick DoS vulnerability (CPU consumption)  -
CVE-2008-3657 - missing 'taintness' checks in dl module  - CVE-2008-3905 -
resolv.rb adds random transactions ids and source ports to prevent DNS spoofing
attacks    [10]http://www.ruby-lang.org/en/news/2008/08/23/dos-vulnerability-in
-
rexml/  - CVE-2008-3790 - DoS in the REXML module    One issue not covered by
any upstream advisory:  - CVE-2008-3443 - DoS in the regular expression engine
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5162", "CVE-2008-1145", "CVE-2008-1447", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
script_summary(english: "Check for the version of the ruby package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ruby-1.8.6.287-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
