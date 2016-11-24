
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2869
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31749);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-2869: centerim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2869 (centerim)");
 script_set_attribute(attribute: "description", value: "CenterIM is a text mode menu- and window-driven IM interface that supports
the ICQ2000, Yahoo!, MSN, AIM TOC, IRC, Gadu-Gadu and Jabber protocols.
Internal RSS reader and a client for LiveJournal are provided.

-
Update Information:

This update fixes the CVE-2008-1467 security issue by disabling the 'actions'
configuration altogether. Furthermore the default web browser is no longer
configurable in CenterIM. The links get open in the default web browser
configured, using xdg-utils.    There won't be any update for centericq. All
users of centericq packages are advised to switch to centerim. In Fedora 7
centerim package provides symbolic link 'centericq' that points to centerim
binary for compatibility with centericq. Note that centerim packages in later
releases of Fedora no longer provide this. CenterIM will automatically use
CenterICQ settings if ones are found in all releases of Fedora.    This release
adds support for new versions of Yahoo IM protocol. Unless you apply this
update, you won't be able to use Yahoo IM after April 2nd 2008.    Please note:
To avoid compatibility and confidentiality problems with an undocumented
protocol transported unencrypted over third-party controlled network, all users
of Yahoo IM protocol are encouraged to switch to open and free alternatives,
such as XMPP used in Jabber network.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1467");
script_summary(english: "Check for the version of the centerim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"centerim-4.22.4-1.fc7.1", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
