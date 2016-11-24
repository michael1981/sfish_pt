# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-14.xml
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
 script_id(28197);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-14");
 script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-5334", "CVE-2007-5335", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-14
(Mozilla Firefox, SeaMonkey, XULRunner: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in Mozilla Firefox and
    SeaMonkey. Various errors in the browser engine and the Javascript
    engine can be exploited to cause a memory corruption (CVE-2007-5339 and
    CVE-2007-5340). Before being used in a request, input passed to the
    user ID when making an HTTP request with digest authentication is not
    properly sanitised (CVE-2007-2292). The titlebar can be hidden by a XUL
    markup language document (CVE-2007-5334). Additionally, an error exists
    in the handling of "smb:" and "sftp:" URI schemes on systems with
    gnome-vfs support (CVE-2007-5337). An unspecified error in the handling
    of "XPCNativeWrappers" and not properly implementing JavaScript
    onUnload() handlers may allow the execution of arbitrary Javascript
    code (CVE-2007-5338 and CVE-2007-1095). Another error is triggered by
    using the addMicrosummaryGenerator sidebar method to access file: URIs
    (CVE-2007-5335).
  
Impact

    A remote attacker could exploit these issues to execute arbitrary code,
    gain the privileges of the user running the application, disclose
    sensitive information, conduct phishing attacks, and read and
    manipulate certain data.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-2.0.0.9"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-2.0.0.9"
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.1.6"
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-bin-1.1.6"
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/xulrunner-1.8.1.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1095');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2292');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5334');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5335');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5337');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5338');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5339');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5340');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-14] Mozilla Firefox, SeaMonkey, XULRunner: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox, SeaMonkey, XULRunner: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/xulrunner", unaffected: make_list("ge 1.8.1.9"), vulnerable: make_list("lt 1.8.1.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.9"), vulnerable: make_list("lt 2.0.0.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.1.6"), vulnerable: make_list("lt 1.1.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey-bin", unaffected: make_list("ge 1.1.6"), vulnerable: make_list("lt 1.1.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.9"), vulnerable: make_list("lt 2.0.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
