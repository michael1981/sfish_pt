
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10743
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42378);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-10743: squidGuard");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10743 (squidGuard)");
 script_set_attribute(attribute: "description", value: "squidGuard can be used to
- limit the web access for some users to a list of accepted/well known
web servers and/or URLs only.
- block access to some listed or blacklisted web servers and/or URLs
for some users.
- block access to URLs matching a list of regular expressions or words
for some users.
- enforce the use of domainnames/prohibit the use of IP address in
URLs.
- redirect blocked URLs to an 'intelligent' CGI based info page.
- redirect unregistered user to a registration form.
- redirect popular downloads like Netscape, MSIE etc. to local copies.
- redirect banners to an empty GIF.
- have different access rules based on time of day, day of the week,
date etc.
- have different rules for different user groups.
- and much more..

Neither squidGuard nor Squid can be used to
- filter/censor/edit text inside documents
- filter/censor/edit embeded scripting languages like JavaScript or
VBscript inside HTML

-
Update Information:

Fixes language file issue, but more importantly. . .    ---------------
squidGuard upstream has released patches fixing (quoting  from upstream
advisories):    a, This patch fixes one buffer overflow problem in sgLog.c when
overlong URLs  are requested. SquidGuard will then go into emergency mode were
no blocking  occurs. This is not required in this situation.    URL:
[9]http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091015  ----
b, This patch fixes two bypass problems with URLs which length is close to the
limit defined by MAX_BUF (default: 4096) in squidGuard and MAX_URL (default:
4096 in squid 2.x and 8192 in squid 3.x) in squid. For this kind of URLs the
proxy request exceeds MAX_BUF causing squidGuard to complain about not being
able to parse the squid request.    URL:
[10]http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091019  ----
References:  -----------  [11]http://secunia.com/advisories/37107/
[12]http://www.securityfocus.com/bid/36800/info
[13]http://www.nntpnews.net/f3468/ports-139844-maintainer-update-www-squidguard
-fix-
security-vulnerabilities-11997445/    Upstream patches - squidGuard 1.4:
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3700");
script_summary(english: "Check for the version of the squidGuard package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"squidGuard-1.4-8.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
