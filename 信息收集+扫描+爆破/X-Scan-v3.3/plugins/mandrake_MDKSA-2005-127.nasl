
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20421);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:127-1: mozilla-thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:127-1 (mozilla-thunderbird).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were reported and fixed in Thunderbird 1.0.5
and Mozilla 1.7.9. The following vulnerabilities have been backported
and patched for this update:
The native implementations of InstallTrigger and other XPInstall-
related javascript objects did not properly validate that they were
called on instances of the correct type. By passing other objects,
even raw numbers, the javascript interpreter would jump to the wrong
place in memory. Although no proof of concept has been developed we
believe this could be exploited (MFSA 2005-40).
moz_bug_r_a4 reported several exploits giving an attacker the ability
to install malicious code or steal data, requiring only that the user
do commonplace actions like clicking on a link or open the context
menu. The common cause in each case was privileged UI code ('chrome')
being overly trusting of DOM nodes from the content window. Scripts in
the web page can override properties and methods of DOM nodes and
shadow the native values, unless steps are taken to get the true
underlying values (MFSA 2005-41).
Additional checks were added to make sure Javascript eval and Script
objects are run with the privileges of the context that created them,
not the potentially elevated privilege of the context calling them in
order to protect against an additional variant of MFSA 2005-41
(MFSA 2005-44).
In several places the browser UI did not correctly distinguish between
true user events, such as mouse clicks or keystrokes, and synthetic
events genenerated by web content. The problems ranged from minor
annoyances like switching tabs or entering full-screen mode, to a
variant on MFSA 2005-34 Synthetic events are now prevented from
reaching the browser UI entirely rather than depend on each potentially
spoofed function to protect itself from untrusted events
(MFSA 2005-45).
Scripts in XBL controls from web content continued to be run even when
Javascript was disabled. By itself this causes no harm, but it could be
combined with most script-based exploits to attack people running
vulnerable versions who thought disabling javascript would protect
them. In the Thunderbird and Mozilla Suite mail clients Javascript is
disabled by default for protection against denial-of-service attacks
and worms; this vulnerability could be used to bypass that protection
(MFSA 2005-46).
When InstallVersion.compareTo() is passed an object rather than a
string it assumed the object was another InstallVersion without
verifying it. When passed a different kind of object the browser would
generally crash with an access violation. shutdown has demonstrated
that different javascript objects can be passed on some OS versions to
get control over the instruction pointer. We assume this could be
developed further to run arbitrary machine code if the attacker can get
exploit code loaded at a predictable address (MFSA 2005-50).
A child frame can call top.focus() even if the framing page comes from
a different origin and has overridden the focus() routine. The call is
made in the context of the child frame. The attacker would look for a
target site with a framed page that makes this call but doesn't verify
that its parent comes from the same site. The attacker could steal
cookies and passwords from the framed page, or take actions on behalf
of a signed-in user. This attack would work only against sites that use
frames in this manner (MFSA 2005-52).
Parts of the browser UI relied too much on DOM node names without
taking different namespaces into account and verifying that nodes
really were of the expected type. An XHTML document could be used to
create fake elements, for example, with content-defined
properties that the browser would access as if they were the trusted
built-in properties of the expected HTML elements. The severity of the
vulnerability would depend on what the attacker could convince the
victim to do, but could result in executing user-supplied script with
elevated 'chrome' privileges. This could be used to install malicious
software on the victim's machine (MFSA 2005-55).
Improper cloning of base objects allowed web content scripts to walk up
the prototype chain to get to a privileged object. This could be used
to execute code with enhanced privileges (MFSA 2005-56).
The updated packages have been patched to address these issue.
Update:
There was a slight regression in the handling of 'right-click' menus in
the packages previously released that is corrected with this new
update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:127-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
script_summary(english: "Check for the version of the mozilla-thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mozilla-thunderbird-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-devel-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2260", value:TRUE);
 set_kb_item(name:"CVE-2005-2261", value:TRUE);
 set_kb_item(name:"CVE-2005-2265", value:TRUE);
 set_kb_item(name:"CVE-2005-2266", value:TRUE);
 set_kb_item(name:"CVE-2005-2269", value:TRUE);
 set_kb_item(name:"CVE-2005-2270", value:TRUE);
}
exit(0, "Host is not affected");
