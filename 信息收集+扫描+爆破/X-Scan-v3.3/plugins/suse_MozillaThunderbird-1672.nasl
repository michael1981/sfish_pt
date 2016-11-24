
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27124);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Thunderbird: Security Update 1.5.0.4 (MozillaThunderbird-1672)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-1672");
 script_set_attribute(attribute: "description", value: "This update of Mozilla Thunderbird fixes the security 
problems fixed in version 1.5.0.4:  MFSA 
2006-31/CVE-2006-2787: EvalInSandbox in Mozilla Firefox and 
Thunderbird before 1.5.0.4 allows remote attackers to gain 
privileges via javascript that calls the valueOf method on 
objects that were created outside of the sandbox.  MFSA 
2006-32/CVE-2006-2780: Integer overflow in Mozilla Firefox 
and Thunderbird before 1.5.0.4 allows remote attackers to 
cause a denial of service (crash) and possibly execute 
arbitrary code via 'jsstr tagify,' which leads to memory 
corruption.  MFSA 2006-32/CVE-2006-2779: Mozilla Firefox 
and Thunderbird before 1.5.0.4 allow remote attackers to 
cause a denial of service (crash) and possibly execute 
arbitrary code via (1) nested <option> tags in a select 
tag, (2) a DOMNodeRemoved mutation event, (3) 
'Content-implemented tree views,' (4) BoxObjects, (5) the 
XBL implementation, (6) an iframe that attempts to remove 
itself, which leads to memory corruption.  MFSA 
2006-33/CVE-2006-2786: HTTP response smuggling 
vulnerability in Mozilla Firefox and Thunderbird before 
1.5.0.4, when used with certain proxy servers, allows 
remote attackers to cause Firefox to interpret certain 
responses as if they were responses from two different 
sites via (1) invalid HTTP response headers with spaces 
between the header name and the colon, which might not be 
ignored in some cases, or (2) HTTP 1.1 headers through an 
HTTP 1.0 proxy, which are ignored by the proxy but 
processed by the client.  MFSA 2006-35/CVE-2006-2775: 
Mozilla Firefox and Thunderbird before 1.5.0.4 associates 
XUL attributes with the wrong URL under certain unspecified 
circumstances, which might allow remote attackers to bypass 
restrictions by causing a persisted string to be associated 
with the wrong URL.  MFSA 2006-37/CVE-2006-2776: Certain 
privileged UI code in Mozilla Firefox and Thunderbird 
before 1.5.0.4 calls content-defined setters on an object 
prototype, which allows remote attackers to execute code at 
a higher privilege than intended.  MFSA 
2006-38/CVE-2006-2778: The crypto.signText function in 
Mozilla Firefox and Thunderbird before 1.5.0.4 allows 
remote attackers to execute arbitrary code via certain 
optional Certificate Authority name arguments, which causes 
an invalid array index and triggers a buffer overflow.  
MFSA 2006-40/CVE-2006-2781: Double-free vulnerability in 
Mozilla Thunderbird before 1.5.0.4 and SeaMonkey before 
1.0.2 allows remote attackers to cause a denial of service 
(hang) and possibly execute arbitrary code via a VCard that 
contains invalid base64 characters.  MFSA 
2006-42/CVE-2006-2783: Mozilla Firefox and Thunderbird 
before 1.5.0.4 strips the Unicode Byte-order-Mark (BOM) 
from a UTF-8 page before the page is passed to the parser, 
which allows remote attackers to conduct cross-site 
scripting (XSS) attacks via a BOM sequence in the middle of 
a dangerous tag such as SCRIPT.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-1672");
script_end_attributes();

script_cve_id("CVE-2006-2787", "CVE-2006-2780", "CVE-2006-2779", "CVE-2006-2786", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2781", "CVE-2006-2783");
script_summary(english: "Check for the MozillaThunderbird-1672 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.4-2.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.4-2.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
