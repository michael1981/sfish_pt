# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(22145);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200608-03");
 script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-03
(Mozilla Firefox: Multiple vulnerabilities)


    The following vulnerabilities have been reported:
    Benjamin Smedberg discovered that chrome URL\'s could be made to
    reference remote files.
    Developers in the Mozilla community
    looked for and fixed several crash bugs to improve the stability of
    Mozilla clients.
    "shutdown" reports that cross-site scripting
    (XSS) attacks could be performed using the construct
    XPCNativeWrapper(window).Function(...), which created a function that
    appeared to belong to the window in question even after it had been
    navigated to the target site.
    "shutdown" reports that scripts
    granting the UniversalBrowserRead privilege can leverage that into the
    equivalent of the far more powerful UniversalXPConnect since they are
    allowed to "read" into a privileged context.
    "moz_bug_r_a4"
    reports that A malicious Proxy AutoConfig (PAC) server could serve a
    PAC script that can execute code with elevated privileges by setting
    the required FindProxyForURL function to the eval method on a
    privileged object that leaked into the PAC sandbox.
    "moz_bug_r_a4" discovered that Named JavaScript functions have a
    parent object created using the standard Object() constructor
    (ECMA-specified behavior) and that this constructor can be redefined by
    script (also ECMA-specified behavior).
    Igor Bukanov and
    shutdown found additional places where an untimely garbage collection
    could delete a temporary object that was in active use.
    Georgi
    Guninski found potential integer overflow issues with long strings in
    the toSource() methods of the Object, Array and String objects as well
    as string function arguments.
    H. D. Moore reported a testcase
    that was able to trigger a race condition where JavaScript garbage
    collection deleted a temporary variable still being used in the
    creation of a new Function object.
    A malicious page can hijack
    native DOM methods on a document object in another domain, which will
    run the attacker\'s script when called by the victim page.
    Secunia Research has discovered a vulnerability which is caused due
    to an memory corruption error within the handling of simultaneously
    happening XPCOM events. This leads to use of a deleted timer
    object.
    An anonymous researcher for TippingPoint and the Zero
    Day Initiative showed that when used in a web page Java would reference
    properties of the window.navigator object as it started up.
    Thilo Girmann discovered that in certain circumstances a JavaScript
    reference to a frame or window was not properly cleared when the
    referenced content went away.
  
Impact

    A user can be enticed to open specially crafted URLs, visit webpages
    containing malicious JavaScript or execute a specially crafted script.
    These events could lead to the execution of arbitrary code, or the
    installation of malware on the user\'s computer.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.5.0.5"
    Users of the binary package should upgrade as well:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.5.0.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3113');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3677');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3801');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3802');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3803');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3805');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3806');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3807');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3808');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3809');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3810');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3811');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3812');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-03] Mozilla Firefox: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.5.0.5"), vulnerable: make_list("lt 1.5.0.5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.5.0.5"), vulnerable: make_list("lt 1.5.0.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
