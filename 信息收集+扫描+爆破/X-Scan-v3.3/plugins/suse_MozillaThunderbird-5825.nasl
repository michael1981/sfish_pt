
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(34958);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security update to 2.0.0.18 (MozillaThunderbird-5825)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-5825");
 script_set_attribute(attribute: "description", value: "This update brings the Mozilla Thunderbird E-Mail program
to version 2.0.0.18.

It fixes following security problems:

CVE-2008-5012 / MFSA 2008-48: Mozilla Firefox 2.x before
2.0.0.18, Thunderbird 2.x before 2.0.0.18, and SeaMonkey
1.x before 1.1.13 do not properly change the source URI
when processing a canvas element and an HTTP redirect,
which allows remote attackers to bypass the same origin
policy and access arbitrary images that are not directly
accessible to the attacker.  NOTE: this issue can be
leveraged to enumerate software on the client by performing
redirections related to moz-icon.




CVE-2008-5014 / MFSA 2008-50

jslock.cpp in Mozilla Firefox 3.x before 3.0.2, Firefox 2.x
before 2.0.0.18, Thunderbird 2.x before 2.0.0.18, and
SeaMonkey 1.x before 1.1.13 allows remote attackers to
cause a denial of service (crash) and possibly execute
arbitrary code by modifying the window.__proto__.__proto__
object in a way that causes a lock on a non-native object,
which triggers an assertion failure related to the
OBJ_IS_NATIVE function.


CVE-2008-5016 / MFSA 2008-52:

The layout engine in Mozilla Firefox 3.x before 3.0.4,
Thunderbird 2.x before 2.0.0.18, and SeaMonkey 1.x before
1.1.13 allows remote attackers to cause a denial of service
(crash) via multiple vectors that trigger an assertion
failure or other consequences.

CVE-2008-5017 / MFSA 2008-52: Integer overflow in
xpcom/io/nsEscape.cpp in the browser engine in Mozilla
Firefox 3.x before 3.0.4, Firefox 2.x before 2.0.0.18,
Thunderbird 2.x before 2.0.0.18, and SeaMonkey 1.x before
1.1.13 allows remote attackers to cause a denial of service
(crash) via unknown vectors.

CVE-2008-5018 / MFSA 2008-52: The JavaScript engine in
Mozilla Firefox 3.x before 3.0.4, Firefox 2.x before
2.0.0.18, Thunderbird 2.x before 2.0.0.18, and SeaMonkey
1.x before 1.1.13 allows remote attackers to cause a denial
of service (crash) via vectors related to 'insufficient
class checking' in the Date class. CVE-2008-5019 / MFSA
2008-53: The session restore feature in Mozilla Firefox 3.x
before 3.0.4 and 2.x before 2.0.0.18 allows remote
attackers to violate the same origin policy to conduct
cross-site scripting (XSS) attacks and execute arbitrary
JavaScript with chrome privileges via unknown vectors.

CVE-2008-5021 / MFSA 2008-55: nsFrameManager in Firefox 3.x
before 3.0.4, Firefox 2.x before 2.0.0.18, Thunderbird 2.x
before 2.0.0.18, and SeaMonkey 1.x before 1.1.13 allows
remote attackers to cause a denial of service (crash) and
possibly execute arbitrary code by modifying properties of
a file input element while it is still being initialized,
then using the blur method to access uninitialized memory.

CVE-2008-5022 / MFSA 2008-56: The
nsXMLHttpRequest::NotifyEventListeners method in Firefox
3.x before 3.0.4, Firefox 2.x before 2.0.0.18, Thunderbird
2.x before 2.0.0.18, and SeaMonkey 1.x before 1.1.13 allows
remote attackers to bypass the same-origin policy and
execute arbitrary script via multiple listeners, which
bypass the inner window check.

CVE-2008-5024 / MFSA 2008-58: Mozilla Firefox 3.x before
3.0.4, Firefox 2.x before 2.0.0.18, Thunderbird 2.x before
2.0.0.18, and SeaMonkey 1.x before 1.1.13 do not properly
escape quote characters used for XML processing, allows
remote attackers to conduct XML injection attacks via the
default namespace in an E4X document.

CVE-2008-5052 / MFSA 2008-52: The AppendAttributeValue
function in the JavaScript engine in Mozilla Firefox 2.x
before 2.0.0.18, Thunderbird 2.x before 2.0.0.18, and
SeaMonkey 1.x before 1.1.13 allows remote attackers to
cause a denial of service (crash) via unknown vectors that
trigger memory corruption, as demonstrated by
e4x/extensions/regress-410192.js.

MFSA 2008-59: Mozilla developer Boris Zbarsky reported that
a malicious mail message might be able to glean personal
information about the recipient from the mailbox URI (such
as computer account name) if the mail recipient has enabled
JavaScript in mail. If a malicious mail is forwarded
'in-line' to a recipient who has enabled JavaScript, then
comments added by the forwarder could be accessed by
scripts in the message and potentially revealed to the
original malicious author if that message has also been
allowed to load remote content. Scripts in mail messages no
longer have access to the DOM properties .documentURI and
.textContent.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-5825");
script_end_attributes();

script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024", "CVE-2008-5052");
script_summary(english: "Check for the MozillaThunderbird-5825 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.18-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.18-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
