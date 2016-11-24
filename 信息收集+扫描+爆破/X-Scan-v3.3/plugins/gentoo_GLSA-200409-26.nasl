# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-26.xml
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
 script_id(14781);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-26");
 script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0906", "CVE-2004-0907", "CVE-2004-0908", "CVE-2004-0909");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-26
(Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities)


    Mozilla-based products are vulnerable to multiple security issues.
    Firstly routines handling the display of BMP images and VCards contain
    an integer overflow and a stack buffer overrun. Specific pages with
    long links, when sent using the "Send Page" function, and links with
    non-ASCII hostnames could both cause heap buffer overruns.
    Several issues were found and fixed in JavaScript rights handling:
    untrusted script code could read and write to the clipboard, signed
    scripts could build confusing grant privileges dialog boxes, and when
    dragged onto trusted frames or windows, JavaScript links could access
    information and rights of the target frame or window. Finally,
    Mozilla-based mail clients (Mozilla and Mozilla Thunderbird) are
    vulnerable to a heap overflow caused by invalid POP3 mail server
    responses.
  
Impact

    An attacker might be able to run arbitrary code with the rights of the
    user running the software by enticing the user to perform one of the
    following actions: view a specially-crafted BMP image or VCard, use the
    "Send Page" function on a malicious page, follow links with malicious
    hostnames, drag multiple JavaScript links in a row to another window,
    or connect to an untrusted POP3 mail server. An attacker could also use
    a malicious page with JavaScript to disclose clipboard contents or
    abuse previously-given privileges to request XPI installation
    privileges through a confusing dialog.
  
Workaround

    There is no known workaround covering all vulnerabilities.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv your-version
    # emerge your-version
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.3');
script_set_attribute(attribute: 'see_also', value: 'http://www.us-cert.gov/cas/techalerts/TA04-261A.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0902');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0903');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0904');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0905');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0906');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0907');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0908');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0909');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-26] Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/epiphany", unaffected: make_list("ge 1.2.9-r1"), vulnerable: make_list("lt 1.2.9-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
