# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-11.xml
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
 script_id(18270);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-11");
 script_cve_id("CVE-2005-1476", "CVE-2005-1477");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-11
(Mozilla Suite, Mozilla Firefox: Remote compromise)


    The Mozilla Suite and Firefox do not properly protect "IFRAME"
    JavaScript URLs from being executed in context of another URL in the
    history list (CAN-2005-1476). The Mozilla Suite and Firefox also fail
    to verify the "IconURL" parameter of the "InstallTrigger.install()"
    function (CAN-2005-1477). Michael Krax and Georgi Guninski discovered
    that it is possible to bypass JavaScript-injection security checks by
    wrapping the javascript: URL within the view-source: or jar:
    pseudo-protocols (MFSA2005-43).
  
Impact

    A malicious remote attacker could use the "IFRAME" issue to
    execute arbitrary JavaScript code within the context of another
    website, allowing to steal cookies or other sensitive data. By
    supplying a javascript: URL as the "IconURL" parameter of the
    "InstallTrigger.Install()" function, a remote attacker could also
    execute arbitrary JavaScript code. Combining both vulnerabilities with
    a website which is allowed to install software or wrapping javascript:
    URLs within the view-source: or jar: pseudo-protocols could possibly
    lead to the execution of arbitrary code with user privileges.
  
Workaround

    Affected systems can be protected by disabling JavaScript.
    However, we encourage Mozilla Suite or Mozilla Firefox users to upgrade
    to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0.4"
    All Mozilla Firefox binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0.4"
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.8"
    All Mozilla Suite binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1476');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1477');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/security/announce/mfsa2005-43.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-11] Mozilla Suite, Mozilla Firefox: Remote compromise');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Suite, Mozilla Firefox: Remote compromise');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.8"), vulnerable: make_list("lt 1.7.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.8"), vulnerable: make_list("lt 1.7.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
