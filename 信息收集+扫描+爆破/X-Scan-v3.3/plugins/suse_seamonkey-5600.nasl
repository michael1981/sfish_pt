
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
 script_id(34201);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security update to 1.1.11 (seamonkey-5600)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-5600");
 script_set_attribute(attribute: "description", value: "Seamonkey was updated to version 1.1.11.

Problems fixed in the 1.1.11 update: CVE-2008-2785 MFSA
2008-34: An anonymous researcher, via TippingPoint's Zero
Day Initiative program, reported a vulnerability in
Mozilla's internal CSSValue array data structure. The
vulnerability was caused by an insufficiently sized
variable being used as a reference counter for CSS objects.
By creating a very large number of references to a common
CSS object, this counter could be overflowed which could
cause a crash when the browser attempts to free the CSS
object while still in use. An attacker could use this crash
to run arbitrary code on the victim's computer.

Problems fixed in the 1.1.10 update: CVE-2008-2811 MFSA
2008-33: Security research firm Astabis reported a
vulnerability in Firefox 2 submitted through the iSIGHT
Partners GVP Program by Greg McManus, Primary GVP
Researcher. The reported crash in Mozilla's block reflow
code could be used by an attacker to crash the browser and
run arbitrary code on the victim's computer.

CVE-2008-2810 MFSA-2008-32: Mozilla community member Geoff
reported a vulnerability in the way Mozilla opens URL files
sent directly to the browser. He demonstrated that such
files were opened with local file privileges, giving the
remote content access to read from the local filesystem. If
a user opened a bookmark to a malicious page in this
manner, the page could potentially read from other local
files on the user's computer.

CVE-2008-2809 MFSA-2008-31: Mozilla developer John G. Myers
reported a weakness in the trust model used by Mozilla
regarding alternate names on self-signed certificates. A
user could be prompted to accept a self-signed certificate
from a website which includes alt-name entries. If the user
accepted the certificate, they would also extend trust to
any alternate domains listed in the certificate, despite
not being prompted about the additional domains. This
technique could be used by an attacker to impersonate
another server.

CVE-2008-2808 MFSA-2008-30: Mozilla contributor Masahiro
Yamada reported that file URLs in directory listings were
not being HTML escaped properly when the filenames
contained particular characters. This resulted in files
from directory listings being opened in unintended ways or
files not being able to be opened by the browser altogether.

CVE-2008-2807 MFSA-2008-29: Mozilla developer Daniel
Glazman demonstrated that an improperly encoded .properties
file in an add-on can result in uninitialized memory being
used. This could potentially result in small chunks of data
from other programs being exposed in the browser.

CVE-2008-2806 MFSA-2008-28: Security researcher Gregory
Fleischer reported a vulnerability in the way Mozilla
indicates the origin of a document to the Java plugin. This
vulnerability could allow a malicious Java applet to bypass
the same-origin policy and create arbitrary socket
connections to other domains.

CVE-2008-2805 MFSA-2008-27: Opera developer Claudio
Santambrogio reported a vulnerability which allows
malicious content to force the browser into uploading local
files to the remote server. This could be used by an
attacker to steal arbitrary files from a victim's computer.

MFSA-2008-26: As a follow-up to vulnerability reported in
MFSA 2008-12 Mozilla has checked similar constructs in the
rest of the MIME handling code. Although no further buffer
overflows were found we changed several function calls to
use safer versions of the string routines that will be more
robust in the face of future code changes.

CVE-2008-2803 MFSA-2008-25: Mozilla contributor
moz_bug_r_a4 reported a vulnerability which allows
arbitrary JavaScript to be executed with chrome privileges.
The privilege escalation was possible because JavaScript
loaded via mozIJSSubScriptLoader.loadSubScript() was not
using XPCNativeWrappers when accessing content. This could
allow an attacker to overwrite trusted objects with
arbitrary code which would be executed with chrome
privileges when the trusted objects were called by the
browser.

CVE-2008-2802 MFSA-2008-24: Mozilla contributor
moz_bug_r_a4 reported a vulnerability that allowed
non-priviliged XUL documents to load chrome scripts from
the fastload file. This could allow an attacker to run
arbitrary JavaScript code with chrome privileges.


CVE-2008-2801 MFSA-2008-23: Security researcher Collin
Jackson reported a series of vulnerabilities which allow
JavaScript to be injected into signed JARs and executed
under the context of the JAR's signer. This could allow an
attacker to run JavaScript in a victim's browser with the
privileges of a different website, provided the attacker
possesses a JAR signed by the other website.

CVE-2008-2800 MFSA-2008-22: Mozilla contributor
moz_bug_r_a4 submitted a set of vulnerabilities which allow
scripts from one document to be executed in the context of
a different document. These vulnerabilities could be used
by an attacker to violate the same-origin policy and
perform an XSS attack.

CVE-2008-2798 CVE-2008-2799 MFSA-2008-21: Mozilla
developers identified and fixed several stability bugs in
the browser engine used in Firefox and other Mozilla-based
products. Some of these crashes showed evidence of memory
corruption under certain circumstances and we presume that
with enough effort at least some of these could be
exploited to run arbitrary code.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-5600");
script_end_attributes();

script_cve_id("CVE-2008-2785", "CVE-2008-2811", "CVE-2008-2810", "CVE-2008-2809", "CVE-2008-2808", "CVE-2008-2807", "CVE-2008-2806", "CVE-2008-2805", "CVE-2008-2803", "CVE-2008-2802", "CVE-2008-2801", "CVE-2008-2800", "CVE-2008-2798", "CVE-2008-2799");
script_summary(english: "Check for the seamonkey-5600 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.11-3.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
